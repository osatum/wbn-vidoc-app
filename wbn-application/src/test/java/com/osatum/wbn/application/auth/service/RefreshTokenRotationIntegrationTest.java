package com.osatum.wbn.application.auth.service;

import com.osatum.wbn.application.auth.dto.AuthResult;
import com.osatum.wbn.application.auth.dto.AutorizeIpRequest;
import com.osatum.wbn.application.auth.port.AccessTokenService;
import com.osatum.wbn.application.auth.port.PreAuthTokenService;
import com.osatum.wbn.application.institution.mapper.InstitutionAccessDtoMapper;
import com.osatum.wbn.application.institution.mapper.InstitutionMembershipAccessDtoMapper;
import com.osatum.wbn.application.security.CurrentActorProvider;
import com.osatum.wbn.application.security.PublicRequestRateLimiter;
import com.osatum.wbn.application.shared.request.ClientRequestMetadata;
import com.osatum.wbn.application.system.service.NavigationAuditVisitService;
import com.osatum.wbn.domain.model.EntityState;
import com.osatum.wbn.domain.model.institution.AuthMode;
import com.osatum.wbn.domain.model.institution.Institution;
import com.osatum.wbn.domain.model.institution.InstitutionType;
import com.osatum.wbn.domain.repository.institution.InstitutionMembershipRepository;
import com.osatum.wbn.domain.repository.institution.InstitutionRepository;
import com.osatum.wbn.domain.repository.user.UserRepository;
import com.osatum.wbn.domain.service.institution.InstitutionIpMatcherService;
import com.osatum.wbn.infrastructure.persistence.LoginSessionRepositoryAdapter;
import com.osatum.wbn.infrastructure.persistence.RefreshTokenRepositoryAdapter;
import com.osatum.wbn.infrastructure.persistence.springdata.RefreshTokenSpringDataRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@SpringJUnitConfig(RefreshTokenRotationIntegrationTest.Config.class)
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:refresh-token-rotation;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE;NON_KEYWORDS=VALUE",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "app.security.jwt.refresh-ttl-days=7"
})
@MockitoBean(types = {UserRepository.class, PasswordEncoder.class, PreAuthTokenService.class,
        CurrentActorProvider.class, InstitutionMembershipRepository.class, InstitutionAccessDtoMapper.class,
        InstitutionMembershipAccessDtoMapper.class, LoginSessionListQueryHandler.class, NavigationAuditVisitService.class,
        PublicRequestRateLimiter.class})
class RefreshTokenRotationIntegrationTest {
    private static final ClientRequestMetadata REQUEST = new ClientRequestMetadata("192.0.2.10", "JUnit");

    @TestConfiguration
    @EnableAutoConfiguration
    @EntityScan("com.osatum.wbn.domain.model")
    @EnableJpaRepositories(basePackageClasses = RefreshTokenSpringDataRepository.class)
    @Import({AuthService.class, LoginSessionService.class, LoginSessionRepositoryAdapter.class,
            RefreshTokenRepositoryAdapter.class})
    static class Config {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    @Autowired private AuthService authService;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;
    @MockitoBean private InstitutionRepository institutionRepository;
    @MockitoBean private InstitutionIpMatcherService ipMatcher;
    @MockitoBean private AccessTokenService accessTokenService;

    @Test
    void concurrentRefreshesIssueOnlyOneSuccessor() throws Exception {
        var login = login();
        long sessionId = sessionId(login);
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        Callable<Optional<AuthResult>> refresh = () -> {
            ready.countDown();
            if (!start.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Parallel refresh did not start");
            }
            try {
                return Optional.of(authService.refresh(login.refreshToken(), REQUEST));
            } catch (BadCredentialsException invalidToken) {
                return Optional.empty();
            }
        };

        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(refresh);
            var second = executor.submit(refresh);
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            var a = first.get(10, TimeUnit.SECONDS);
            var b = second.get(10, TimeUnit.SECONDS);
            assertThat(a.isPresent()).isNotEqualTo(b.isPresent());
            assertThat(a.orElseGet(b::orElseThrow).refreshToken()).isNotEqualTo(login.refreshToken());
        }

        assertThat(jdbc.queryForObject("select count(*) from refresh_token where login_session_id = ?",
                Integer.class, sessionId)).isEqualTo(2);
        assertThat(jdbc.queryForObject("select count(*) from refresh_token where login_session_id = ? and not revoked",
                Integer.class, sessionId)).isEqualTo(1);
    }

    @Test
    void logoutUsingPreviousCookieBlocksItsSuccessor() {
        var login = login();
        var successor = authService.refresh(login.refreshToken(), REQUEST);

        authService.logout(login.refreshToken());

        assertThat(jdbc.queryForObject("select status from login_session where id = ?",
                String.class, sessionId(login))).isEqualTo("LOGGED_OUT");
        assertThatThrownBy(() -> authService.refresh(successor.refreshToken(), REQUEST))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void aRevokedSessionBlocksRefreshEvenWhenTheTokenIsStillUnconsumed() {
        var login = login();
        long sessionId = sessionId(login);
        jdbc.update("update login_session set status = 'REVOKED', ended_at = current_timestamp where id = ?", sessionId);

        assertThatThrownBy(() -> authService.refresh(login.refreshToken(), REQUEST))
                .isInstanceOf(BadCredentialsException.class);
        assertThat(jdbc.queryForObject("select count(*) from refresh_token where login_session_id = ?",
                Integer.class, sessionId)).isEqualTo(1);
    }

    @Test
    void ipDenialPersistsSessionAndTokenRevocation() {
        var login = login();
        long sessionId = sessionId(login);
        var outsideNetwork = new ClientRequestMetadata("198.51.100.20", "JUnit");
        when(ipMatcher.matchesInstitution(anyLong(), eq(outsideNetwork.ipAddress()))).thenReturn(false);

        assertThatThrownBy(() -> authService.refresh(login.refreshToken(), outsideNetwork))
                .isInstanceOf(IpAccessDeniedException.class);
        assertThat(jdbc.queryForObject("select status from login_session where id = ?",
                String.class, sessionId)).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("select revoked from refresh_token where login_session_id = ?",
                Boolean.class, sessionId)).isTrue();
    }

    private AuthResult login() {
        Institution institution = new TransactionTemplate(transactionManager).execute(transaction -> {
            var saved = new Institution();
            saved.setName("Refresh integration test");
            saved.setState(EntityState.ACTIVE);
            saved.setAuthMode(AuthMode.AUTH_NOT_REQUIRED);
            saved.setInstitutionType(InstitutionType.RESEARCH_UNIT);
            entityManager.persist(saved);
            return saved;
        });
        when(institutionRepository.findById(institution.getId())).thenReturn(Optional.of(institution));
        when(ipMatcher.matchesInstitution(institution.getId(), REQUEST.ipAddress())).thenReturn(true);
        when(accessTokenService.createInstitutionAccessToken(any(), any(), any(), anyLong()))
                .thenAnswer(invocation -> invocation.getArgument(3).toString());
        return authService.autorizeIp(new AutorizeIpRequest(institution.getId(), institution.getName()), REQUEST);
    }

    private long sessionId(AuthResult result) {
        return Long.parseLong(result.response().getAccessToken());
    }
}
