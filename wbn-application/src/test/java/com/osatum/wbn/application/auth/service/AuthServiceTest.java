package com.osatum.wbn.application.auth.service;

import com.osatum.wbn.application.auth.dto.AuthStatus;
import com.osatum.wbn.application.auth.dto.SelectInstitutionAndRoleRequest;
import com.osatum.wbn.application.auth.port.AccessTokenService;
import com.osatum.wbn.application.auth.port.PreAuthTokenService;
import com.osatum.wbn.application.institution.mapper.InstitutionAccessDtoMapper;
import com.osatum.wbn.application.institution.mapper.InstitutionMembershipAccessDtoMapper;
import com.osatum.wbn.application.security.CurrentActorProvider;
import com.osatum.wbn.application.security.PublicRequestRateLimiter;
import com.osatum.wbn.application.security.UserActor;
import com.osatum.wbn.application.shared.request.ClientRequestMetadata;
import com.osatum.wbn.domain.model.EntityState;
import com.osatum.wbn.domain.model.auth.LoginSession;
import com.osatum.wbn.domain.model.auth.RefreshToken;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final ClientRequestMetadata REQUEST = new ClientRequestMetadata("192.0.2.10", "JUnit");
    private static final UserActor SOURCE_ACTOR = new UserActor(
            10L, "user@example.org", 11L, InstitutionType.RESEARCH_UNIT, InstitutionRole.INSTITUTION_USER, 12L);

    private final UserRepository userRepository = mock(UserRepository.class);
    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private final PreAuthTokenService preAuthTokenService = mock(PreAuthTokenService.class);
    private final CurrentActorProvider currentActorProvider = mock(CurrentActorProvider.class);
    private final LoginSessionService loginSessionService = mock(LoginSessionService.class);
    private final InstitutionIpMatcherService ipMatcherService = mock(InstitutionIpMatcherService.class);
    private final InstitutionMembershipRepository membershipRepository = mock(InstitutionMembershipRepository.class);
    private AuthService service;

    @BeforeEach
    void setUp() {
        service = new AuthService(
                userRepository,
                refreshTokenRepository,
                mock(org.springframework.security.crypto.password.PasswordEncoder.class),
                accessTokenService,
                preAuthTokenService,
                currentActorProvider,
                mock(InstitutionRepository.class),
                membershipRepository,
                ipMatcherService,
                mock(InstitutionAccessDtoMapper.class),
                mock(InstitutionMembershipAccessDtoMapper.class),
                loginSessionService,
                mock(PublicRequestRateLimiter.class)
        );
        ReflectionTestUtils.setField(service, "refreshTtlDays", 7L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void selectsContextUsingAuthenticatedUserWithoutPreAuthCookie() {
        AppUser user = activeUser(10L);
        Institution institution = activeInstitution(20L, InstitutionType.SYSTEM_OPERATOR);
        InstitutionMembership membership = activeMembership(30L, institution, InstitutionRole.INSTITUTION_ADMIN);
        membership.setLoginAllowedFromAnyIp(false);
        user.setMemberships(Set.of(membership));

        LoginSession session = new LoginSession();
        session.setId(40L);
        mockSourceSession();
        when(ipMatcherService.matchesInstitution(SOURCE_ACTOR.institutionId(), REQUEST.ipAddress())).thenReturn(true);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(ipMatcherService.matchesInstitution(institution.getId(), REQUEST.ipAddress())).thenReturn(true);
        when(loginSessionService.startUserSession(
                eq(user),
                eq(institution),
                eq(InstitutionRole.INSTITUTION_ADMIN),
                any(ClientRequestMetadata.class),
                any()
        )).thenReturn(session);
        when(accessTokenService.createUserAccessToken(
                user,
                institution.getId(),
                institution.getInstitutionType(),
                membership.getRole(),
                session.getId()
        )).thenReturn("switched-access-token");

        var result = service.selectInstitution(
                new SelectInstitutionAndRoleRequest(institution.getId(), membership.getId()),
                null,
                REQUEST
        );

        assertThat(result.response().getStatus()).isEqualTo(AuthStatus.OK);
        assertThat(result.response().getAccessToken()).isEqualTo("switched-access-token");
        assertThat(result.response().getInstitutionType()).isEqualTo(InstitutionType.SYSTEM_OPERATOR);
        verify(preAuthTokenService, never()).requireUserIdFromPreAuthToken(any());
        verify(ipMatcherService).matchesInstitution(SOURCE_ACTOR.institutionId(), REQUEST.ipAddress());
        verify(ipMatcherService).matchesInstitution(institution.getId(), REQUEST.ipAddress());
    }

    @Test
    void rejectsContextSelectionFromAnEndedSession() {
        when(currentActorProvider.findCurrentActor()).thenReturn(Optional.of(SOURCE_ACTOR));

        assertThatThrownBy(() -> service.selectInstitution(
                new SelectInstitutionAndRoleRequest(20L, 30L), "pre-auth-cookie", REQUEST))
                .isInstanceOf(BadCredentialsException.class);

        verify(loginSessionService).isActive(SOURCE_ACTOR.loginSessionId());
        verify(loginSessionService, never()).startUserSession(any(), any(), any(), any(), any());
        verifyNoInteractions(preAuthTokenService, refreshTokenRepository, accessTokenService);
    }

    @Test
    void rejectsContextSelectionWhenSourceInstitutionDoesNotAllowTheRequestIp() {
        mockSourceSession();

        assertThatThrownBy(() -> service.selectInstitution(
                new SelectInstitutionAndRoleRequest(20L, 30L), null, REQUEST))
                .isInstanceOf(IpAccessDeniedException.class);

        verify(ipMatcherService).matchesInstitution(SOURCE_ACTOR.institutionId(), REQUEST.ipAddress());
        verify(loginSessionService, never()).startUserSession(any(), any(), any(), any(), any());
        verifyNoInteractions(preAuthTokenService, refreshTokenRepository, accessTokenService);
    }

    @Test
    void selectsFirstContextFromPreAuthCookieWithoutSourceSession() {
        AppUser user = activeUser(10L);
        Institution institution = activeInstitution(20L, InstitutionType.SYSTEM_OPERATOR);
        InstitutionMembership membership = activeMembership(30L, institution, InstitutionRole.INSTITUTION_ADMIN);
        membership.setLoginAllowedFromAnyIp(true);
        user.setMemberships(Set.of(membership));
        when(preAuthTokenService.requireUserIdFromPreAuthToken("pre-auth-cookie")).thenReturn(user.getId());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        LoginSession session = new LoginSession();
        session.setId(40L);
        when(loginSessionService.startUserSession(eq(user), eq(institution), eq(membership.getRole()), eq(REQUEST), any()))
                .thenReturn(session);

        var result = service.selectInstitution(
                new SelectInstitutionAndRoleRequest(institution.getId(), membership.getId()), "pre-auth-cookie", REQUEST);

        assertThat(result.response().getStatus()).isEqualTo(AuthStatus.OK);
        assertThat(result.refreshToken()).isNotBlank();
        verify(loginSessionService, never()).isActive(any());
    }

    private void mockSourceSession() {
        Institution source = activeInstitution(SOURCE_ACTOR.institutionId(), SOURCE_ACTOR.institutionType());
        InstitutionMembership membership = activeMembership(39L, source, SOURCE_ACTOR.institutionRole());
        when(currentActorProvider.findCurrentActor()).thenReturn(Optional.of(SOURCE_ACTOR));
        when(loginSessionService.isActive(SOURCE_ACTOR.loginSessionId())).thenReturn(true);
        when(membershipRepository.findByUserIdAndInstitutionIdAndRole(
                SOURCE_ACTOR.userId(), SOURCE_ACTOR.institutionId(), SOURCE_ACTOR.institutionRole()))
                .thenReturn(Optional.of(membership));
    }

    private AppUser activeUser(Long id) {
        AppUser user = new AppUser();
        user.setId(id);
        user.setEmail("user@example.org");
        user.setState(EntityState.ACTIVE);
        return user;
    }

    private Institution activeInstitution(Long id, InstitutionType type) {
        Institution institution = new Institution();
        institution.setId(id);
        institution.setName("System operator");
        institution.setInstitutionType(type);
        institution.setState(EntityState.ACTIVE);
        return institution;
    }

    private InstitutionMembership activeMembership(Long id, Institution institution, InstitutionRole role) {
        InstitutionMembership membership = new InstitutionMembership();
        membership.setId(id);
        membership.setInstitution(institution);
        membership.setRole(role);
        membership.setState(EntityState.ACTIVE);
        return membership;
    }
}
