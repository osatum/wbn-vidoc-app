package com.osatum.wbn.web.auth.controller;

import com.osatum.wbn.application.auth.service.LoginSessionService;
import com.osatum.wbn.application.notification.service.EmailMessageLogService;
import com.osatum.wbn.application.notification.service.EmailTemplateService;
import com.osatum.wbn.application.system.authorization.SystemAuthorization;
import com.osatum.wbn.application.user.service.AccountActivationLogService;
import com.osatum.wbn.domain.model.institution.InstitutionRole;
import com.osatum.wbn.domain.model.institution.InstitutionType;
import com.osatum.wbn.infrastructure.security.IpAccessEnforcementFilter;
import com.osatum.wbn.infrastructure.security.JwtAuthFilter;
import com.osatum.wbn.infrastructure.security.LoginSessionActivityFilter;
import com.osatum.wbn.infrastructure.security.SecurityConfig;
import com.osatum.wbn.infrastructure.security.SpringSecurityCurrentActorProvider;
import com.osatum.wbn.infrastructure.security.principal.UserPrincipal;
import com.osatum.wbn.web.notification.controller.EmailMessageLogController;
import com.osatum.wbn.web.notification.controller.EmailTemplateController;
import com.osatum.wbn.web.user.registration.controller.AccountActivationLogController;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.List;

import static com.osatum.wbn.domain.model.institution.InstitutionRole.INSTITUTION_ADMIN;
import static com.osatum.wbn.domain.model.institution.InstitutionRole.INSTITUTION_VIEWER;
import static com.osatum.wbn.domain.model.institution.InstitutionType.RESEARCH_UNIT;
import static com.osatum.wbn.domain.model.institution.InstitutionType.SYSTEM_OPERATOR;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

@SpringJUnitWebConfig(OperatorAdministrationAuthorizationTest.Config.class)
class OperatorAdministrationAuthorizationTest {
    private static final String ACTOR = "testActor";

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @Import({SecurityConfig.class, SystemAuthorization.class, SpringSecurityCurrentActorProvider.class,
            AuthSessionController.class, AccountActivationLogController.class, EmailMessageLogController.class,
            EmailTemplateController.class})
    static class Config {
    }

    @Autowired private WebApplicationContext context;
    @Autowired private FilterChainProxy security;
    @MockitoBean private JwtAuthFilter jwt;
    @MockitoBean private IpAccessEnforcementFilter ip;
    @MockitoBean private LoginSessionActivityFilter activity;
    @MockitoBean private LoginSessionService sessions;
    @MockitoBean private AccountActivationLogService activations;
    @MockitoBean private EmailMessageLogService messages;
    @MockitoBean private EmailTemplateService templates;

    private MockMvc mvc;

    @BeforeEach
    void setup() throws Exception {
        doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            if (request.getAttribute(ACTOR) instanceof Authentication authentication) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            invocation.<FilterChain>getArgument(2).doFilter(request, invocation.getArgument(1));
            return null;
        }).when(jwt).doFilter(any(ServletRequest.class), any(ServletResponse.class), any(FilterChain.class));
        for (var filter : List.of(ip, activity)) {
            doAnswer(invocation -> {
                invocation.<FilterChain>getArgument(2).doFilter(invocation.getArgument(0), invocation.getArgument(1));
                return null;
            }).when(filter).doFilter(any(ServletRequest.class), any(ServletResponse.class), any(FilterChain.class));
        }
        mvc = webAppContextSetup(context).addFilters(security).build();
    }

    @Test
    void rejectsGuestsAndDeniesAnAdministratorOutsideTheOperatorContext() throws Exception {
        for (var request : endpoints()) {
            mvc.perform(request).andExpect(status().isUnauthorized());
            mvc.perform(request.requestAttr(ACTOR, actor(RESEARCH_UNIT, INSTITUTION_ADMIN, "ADMIN")))
                    .andExpect(status().isForbidden());
            mvc.perform(request.requestAttr(ACTOR, actor(SYSTEM_OPERATOR, INSTITUTION_VIEWER, "ADMIN")))
                    .andExpect(status().isForbidden());
        }
        verifyNoInteractions(sessions, activations, messages, templates);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN", "USER"})
    void allowsAdministratorInOperatorContext(String authority) throws Exception {
        for (var request : endpoints()) {
            mvc.perform(request.requestAttr(ACTOR, actor(SYSTEM_OPERATOR, INSTITUTION_ADMIN, authority)))
                    .andExpect(status().isOk());
        }
        verify(sessions).getLoginSessions(isNull());
        verify(sessions).getLoginSessionsForUser(eq(1L), isNull());
        verify(sessions).getLoginSessionsForInstitution(eq(2L), isNull());
        verify(sessions).getActiveSessions(isNull());
        verify(activations).findActivationLogs(isNull());
        verify(messages).findEmailMessages(isNull());
        verify(messages).resendEmailMessage(3L);
        verify(templates).findTemplates();
        verify(templates).findTemplate(4L);
        verify(templates).updateTemplate(eq(4L), any());
    }

    private List<MockHttpServletRequestBuilder> endpoints() {
        return List.of(
                post("/api/auth-sessions/search"),
                post("/api/auth-sessions/search-for-user/1"),
                post("/api/auth-sessions/search-for-institution/2"),
                post("/api/auth-sessions/active/search"),
                post("/api/account-activations/search"),
                post("/api/email-messages/search"),
                post("/api/email-messages/3/resend"),
                get("/api/email-templates"),
                get("/api/email-templates/4"),
                put("/api/email-templates/4").contentType(MediaType.APPLICATION_JSON).content("""
                        {"name":"Test","language":"pl","subject":"Subject","htmlBody":"Body","state":"ACTIVE"}
                        """)
        );
    }

    private Authentication actor(InstitutionType type, InstitutionRole role, String authority) {
        var principal = UserPrincipal.builder()
                .userId(7L)
                .institutionId(type == SYSTEM_OPERATOR ? 11L : 12L)
                .institutionType(type)
                .institutionRole(role)
                .build();
        return new TestingAuthenticationToken(principal, null, authority);
    }
}
