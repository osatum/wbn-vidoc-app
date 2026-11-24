package com.osatum.wbn.application.auth.service;

import com.osatum.wbn.application.auth.dto.AuthStatus;
import com.osatum.wbn.application.auth.dto.LoginRequest;
import com.osatum.wbn.application.auth.port.AccessTokenService;
import com.osatum.wbn.application.auth.port.PreAuthTokenService;
import com.osatum.wbn.application.institution.mapper.InstitutionAccessDtoMapper;
import com.osatum.wbn.application.institution.mapper.InstitutionMembershipAccessDtoMapper;
import com.osatum.wbn.application.security.CurrentActorProvider;
import com.osatum.wbn.application.security.PublicRequestLimitProperties;
import com.osatum.wbn.application.security.PublicRequestRateLimiter;
import com.osatum.wbn.application.shared.exception.RequestRateLimitExceededException;
import com.osatum.wbn.application.shared.request.ClientRequestMetadata;
import com.osatum.wbn.application.user.service.AccountActivationService;
import com.osatum.wbn.application.user.service.RegistrationInstitutionService;
import com.osatum.wbn.application.user.service.RegistrationSubmitService;
import com.osatum.wbn.domain.model.EntityState;
import com.osatum.wbn.domain.model.auth.LoginSession;
import com.osatum.wbn.domain.model.institution.Institution;
import com.osatum.wbn.domain.model.institution.InstitutionMembership;
import com.osatum.wbn.domain.model.institution.InstitutionRole;
import com.osatum.wbn.domain.model.institution.InstitutionType;
import com.osatum.wbn.domain.model.user.AppUser;
import com.osatum.wbn.domain.repository.auth.RefreshTokenRepository;
import com.osatum.wbn.domain.repository.institution.InstitutionMembershipRepository;
import com.osatum.wbn.domain.repository.institution.InstitutionRepository;
import com.osatum.wbn.domain.repository.user.UserRepository;
import com.osatum.wbn.domain.service.institution.InstitutionIpMatcherService;
import com.osatum.wbn.infrastructure.persistence.PublicRequestLimitRepositoryAdapter;
import com.osatum.wbn.web.error.ApiExceptionHandler;
import com.osatum.wbn.web.shared.request.ClientRequestMetadataResolver;
import com.osatum.wbn.web.user.registration.controller.RegistrationController;
import com.osatum.wbn.web.user.registration.mapper.RegistrationSubmitFormMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

@SpringJUnitConfig(PublicRequestRateLimiterIntegrationTest.Config.class)
@TestPropertySource(properties = "app.security.jwt.refresh-ttl-days=7")
@MockitoBean(types = {RefreshTokenRepository.class, AccessTokenService.class, PreAuthTokenService.class,
        CurrentActorProvider.class, InstitutionIpMatcherService.class, InstitutionAccessDtoMapper.class,
        InstitutionMembershipAccessDtoMapper.class})
class PublicRequestRateLimiterIntegrationTest {
    private static final Instant START = Instant.parse("2026-11-24T08:00:00Z");
    private static final ClientRequestMetadata REQUEST = new ClientRequestMetadata("192.0.2.10", "JUnit");
    private static final String EMAIL = "user@example.test";

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement
    @Import({AuthService.class, RegistrationSubmitService.class, PublicRequestRateLimiter.class,
            PublicRequestLimitRepositoryAdapter.class})
    static class Config {
        @Bean
        DataSource dataSource() {
            var source = new DriverManagerDataSource(
                    "jdbc:h2:mem:public-request-limits;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
            new ResourceDatabasePopulator(new ClassPathResource("db/migration/V15__add_public_request_rate_limits.sql"))
                    .execute(source);
            return source;
        }

        @Bean
        JdbcTemplate jdbcTemplate(DataSource source) {
            return new JdbcTemplate(source);
        }

        @Bean
        JdbcTransactionManager transactionManager(DataSource source) {
            return new JdbcTransactionManager(source);
        }

        @Bean
        MutableClock clock() {
            return new MutableClock();
        }

        @Bean
        PublicRequestLimitProperties limitProperties() {
            var properties = new PublicRequestLimitProperties();
            properties.getLogin().setIpObservationThreshold(2);
            properties.getRegistration().setIpObservationThreshold(2);
            return properties;
        }
    }

    @Autowired private AuthService authService;
    @Autowired private PublicRequestRateLimiter limiter;
    @Autowired private RegistrationSubmitService registrationService;
    @Autowired private MutableClock clock;
    @Autowired private JdbcTemplate jdbc;
    @MockitoBean private UserRepository users;
    @MockitoBean private PasswordEncoder passwordEncoder;
    @MockitoBean private LoginSessionService sessions;
    @MockitoBean private InstitutionRepository institutions;
    @MockitoBean private InstitutionMembershipRepository memberships;
    @MockitoBean private AccountActivationService activation;

    @BeforeEach
    void reset() {
        jdbc.update("delete from public_request_limit");
        clock.time.set(START);
    }

    @Test
    void countsCaseVariantsAndInstitutionsTogetherButLeavesAnotherAccountOnTheSameIpUsable() {
        for (int i = 0; i < 4; i++) {
            assertBadCredentials(EMAIL, 1L);
        }
        assertBadCredentials("USER@EXAMPLE.TEST", 2L);
        assertLimitedFor(30);
        verify(users, times(5)).findByEmail(anyString());

        assertBadCredentials("other@example.test", 1L);

        clock.advance(Duration.ofSeconds(30));
        assertBadCredentials(EMAIL, 1L);
        assertLimitedFor(60);
        clock.advance(Duration.ofSeconds(60));
        assertBadCredentials(EMAIL, 1L);
        assertLimitedFor(120);
        clock.advance(Duration.ofSeconds(120));
        assertBadCredentials(EMAIL, 1L);
        assertLimitedFor(240);
        clock.advance(Duration.ofSeconds(240));
        assertBadCredentials(EMAIL, 1L);
        assertLimitedFor(300);
    }

    @Test
    void allowsLoginWhenCooldownEndsAndResetsTheFailureCount() {
        for (int i = 0; i < 5; i++) {
            assertBadCredentials(EMAIL, 1L);
        }
        clock.advance(Duration.ofSeconds(30));
        allowLogin();
        var result = authService.login(new LoginRequest(EMAIL, "valid-password", 1L, null), REQUEST);
        assertThat(result.response().getStatus()).isEqualTo(AuthStatus.OK);

        for (int i = 0; i < 5; i++) {
            assertBadCredentials(EMAIL, 1L);
        }
        assertLimitedFor(30);
    }

    @Test
    void admitsAtMostFiveFailedCredentialChecksWhenRequestsRunConcurrently() throws Exception {
        var attempts = runConcurrently(8, () -> {
            try {
                loginWithWrongPassword(EMAIL, 1L);
                throw new AssertionError("Wrong credentials were accepted");
            } catch (BadCredentialsException failure) {
                return true;
            } catch (RequestRateLimitExceededException limited) {
                return false;
            }
        });
        assertThat(attempts).filteredOn(Boolean::booleanValue).hasSize(5);
        verify(users, times(5)).findByEmail(EMAIL);
    }

    @Test
    void expiresCountersAndTheirAttemptsAfterTheWindow() {
        assertBadCredentials(EMAIL, 1L);
        clock.advance(Duration.ofMinutes(15));
        limiter.removeExpiredBuckets();
        assertThat(jdbc.queryForObject("select count(*) from public_request_limit", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from public_request_attempt", Integer.class)).isZero();
    }

    @Test
    void returnsTheSameAcceptanceForNewAndExistingAccounts() throws Exception {
        MockMvc mvc = configureRegistration();
        var first = mvc.perform(registration(EMAIL, 1L))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("ACCEPTED"))
                .andExpect(jsonPath("$.institutionId").value(1))
                .andExpect(jsonPath("$.userId").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.membershipId").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.role").doesNotHaveJsonPath())
                .andReturn().getResponse().getContentAsString();

        mvc.perform(registration(EMAIL, 1L))
                .andExpect(status().isAccepted())
                .andExpect(content().string(first));
        verify(users).save(any());
        verify(activation).issueActivationToken(any(), any(), any(), any());
    }

    @Test
    void sharesTheRegistrationQuotaAcrossInstitutionsAndAllowsAnotherAddressFromTheSameIp() throws Exception {
        MockMvc mvc = configureRegistration();
        mvc.perform(registration(EMAIL, 1L)).andExpect(status().isAccepted());
        clock.advance(Duration.ofMinutes(5));
        mvc.perform(registration("USER@EXAMPLE.TEST", 2L)).andExpect(status().isAccepted());
        clock.advance(Duration.ofMinutes(5));
        mvc.perform(registration(EMAIL, 2L)).andExpect(status().isAccepted());

        mvc.perform(registration(EMAIL, 1L)).andExpect(status().isTooManyRequests())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, "1200"))
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));
        mvc.perform(registration("other@example.test", 1L)).andExpect(status().isAccepted());

        clock.advance(Duration.ofMinutes(20));
        mvc.perform(registration(EMAIL, 1L)).andExpect(status().isAccepted());
        verify(users, times(2)).save(any());
    }

    @Test
    void concurrentRegistrationsRespectTheQuotaAndCreateOnlyOneAccount() throws Exception {
        MockMvc mvc = configureRegistration();

        var statuses = runConcurrently(6, () -> mvc.perform(registration(EMAIL, 1L))
                .andReturn().getResponse().getStatus());

        assertThat(statuses).containsExactlyInAnyOrder(202, 202, 202, 429, 429, 429);
        verify(users).save(any());
        verify(activation).issueActivationToken(any(), any(), any(), any());
    }

    private MockMvc configureRegistration() {
        for (long id : List.of(1L, 2L)) {
            var institution = new Institution();
            institution.setId(id);
            institution.setState(EntityState.ACTIVE);
            institution.setInstitutionType(InstitutionType.RESEARCH_UNIT);
            institution.setAllowRegistration(true);
            institution.setAllowOtherIp(true);
            institution.setAllowOtherEmailDomain(true);
            when(institutions.findById(id)).thenReturn(Optional.of(institution));
        }
        var accounts = new ConcurrentHashMap<String, AppUser>();
        when(users.findByEmail(anyString())).thenAnswer(invocation -> Optional.ofNullable(accounts.get(invocation.getArgument(0))));
        when(users.save(any(AppUser.class))).thenAnswer(invocation -> {
            AppUser user = invocation.getArgument(0);
            accounts.put(user.getEmail(), user);
            return user;
        });
        when(memberships.save(any(InstitutionMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(passwordEncoder.encode(anyString())).thenReturn("test-password-hash");

        var metadata = mock(ClientRequestMetadataResolver.class);
        when(metadata.resolve(any())).thenReturn(REQUEST);
        var controller = new RegistrationController(mock(RegistrationInstitutionService.class), registrationService,
                new RegistrationSubmitFormMapper(), activation, metadata, limiter);
        return standaloneSetup(controller).setControllerAdvice(new ApiExceptionHandler()).build();
    }

    private MockHttpServletRequestBuilder registration(String email, long institutionId) {
        return post("/api/registration/institutions/{id}/submit", institutionId)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","firstName":"Jan","lastName":"Test","password":"test-password",
                         "termsAndPrivacyPolicyAccepted":true,"personalDataProcessingAcknowledged":true}
                        """.formatted(email));
    }

    private <T> List<T> runConcurrently(int count, Callable<T> action) throws Exception {
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(count)) {
            List<Future<T>> attempts = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                attempts.add(executor.submit(() -> {
                    if (!start.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent requests did not start");
                    }
                    return action.call();
                }));
            }
            start.countDown();
            List<T> results = new ArrayList<>();
            for (var attempt : attempts) {
                results.add(attempt.get(10, TimeUnit.SECONDS));
            }
            return results;
        }
    }

    private void assertBadCredentials(String email, long institutionId) {
        assertThatThrownBy(() -> loginWithWrongPassword(email, institutionId))
                .isInstanceOf(BadCredentialsException.class);
    }

    private void assertLimitedFor(long seconds) {
        assertThatThrownBy(() -> loginWithWrongPassword(EMAIL, 1L))
                .isInstanceOfSatisfying(RequestRateLimitExceededException.class,
                        error -> assertThat(error.retryAfterSeconds()).isEqualTo(seconds));
    }

    private void loginWithWrongPassword(String email, long institutionId) {
        authService.login(new LoginRequest(email, "wrong-password", institutionId, null), REQUEST);
    }

    private void allowLogin() {
        var institution = new Institution();
        institution.setId(1L);
        institution.setState(EntityState.ACTIVE);
        institution.setInstitutionType(InstitutionType.RESEARCH_UNIT);
        var membership = new InstitutionMembership();
        membership.setInstitution(institution);
        membership.setLoginAllowedFromAnyIp(true);
        membership.setRole(InstitutionRole.INSTITUTION_USER);
        membership.setState(EntityState.ACTIVE);
        var user = new AppUser();
        user.setId(2L);
        user.setState(EntityState.ACTIVE);
        user.setPasswordHash("test-password-hash");
        user.setMemberships(Set.of(membership));
        var session = new LoginSession();
        session.setId(3L);
        when(sessions.startUserSession(any(), any(), any(), any(), any())).thenReturn(session);
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(users.findById(2L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("valid-password", user.getPasswordHash())).thenReturn(true);
    }

    static class MutableClock extends Clock {
        private final AtomicReference<Instant> time = new AtomicReference<>(START);

        void advance(Duration duration) {
            time.updateAndGet(instant -> instant.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(instant(), zone);
        }

        @Override
        public Instant instant() {
            return time.get();
        }
    }
}
