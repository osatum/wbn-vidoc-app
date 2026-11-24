package com.osatum.wbn.web.questionnaire.controller;

import com.osatum.wbn.application.auth.service.LoginSessionService;
import com.osatum.wbn.application.journal.authorization.JournalAuthorization;
import com.osatum.wbn.application.questionnaire.service.QuestionnaireService;
import com.osatum.wbn.application.questionnaire.view.QuestionnaireView;
import com.osatum.wbn.application.report.survey.dto.QuestionnaireReportAvailabilityDto;
import com.osatum.wbn.application.report.survey.dto.SurveyReportResult;
import com.osatum.wbn.application.report.survey.sevice.QuestionnaireReportFileService;
import com.osatum.wbn.application.report.survey.sevice.QuestionnaireReportFileService.QuestionnaireReportFile;
import com.osatum.wbn.application.report.survey.sevice.QuestionnaireReportFileService.QuestionnaireReportLanguage;
import com.osatum.wbn.application.shared.request.ClientRequestMetadata;
import com.osatum.wbn.application.shared.request.ClientRequestMetadataInput;
import com.osatum.wbn.application.shared.request.ClientRequestMetadataResolutionService;
import com.osatum.wbn.domain.model.institution.Institution;
import com.osatum.wbn.domain.model.institution.InstitutionMembership;
import com.osatum.wbn.domain.model.institution.InstitutionRole;
import com.osatum.wbn.domain.model.institution.InstitutionType;
import com.osatum.wbn.domain.model.user.AppUser;
import com.osatum.wbn.domain.repository.auth.RefreshTokenRepository;
import com.osatum.wbn.domain.service.institution.InstitutionIpMatcherService;
import com.osatum.wbn.infrastructure.persistence.springdata.InstitutionMembershipSpringDataRepository;
import com.osatum.wbn.infrastructure.security.IpAccessEnforcementFilter;
import com.osatum.wbn.infrastructure.security.JwtAuthFilter;
import com.osatum.wbn.infrastructure.security.LoginSessionActivityFilter;
import com.osatum.wbn.infrastructure.security.SecurityConfig;
import com.osatum.wbn.infrastructure.security.SpringSecurityCurrentActorProvider;
import com.osatum.wbn.infrastructure.security.principal.InstitutionPrincipal;
import com.osatum.wbn.infrastructure.security.principal.UserPrincipal;
import com.osatum.wbn.web.report.controller.QuestionnaireReportController;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ByteArrayResource;
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
import java.util.Optional;

import static com.osatum.wbn.domain.model.institution.InstitutionRole.INSTITUTION_ADMIN;
import static com.osatum.wbn.domain.model.institution.InstitutionRole.INSTITUTION_TO_CONFIRM;
import static com.osatum.wbn.domain.model.institution.InstitutionRole.INSTITUTION_VIEWER;
import static com.osatum.wbn.domain.model.institution.InstitutionType.RESEARCH_UNIT;
import static com.osatum.wbn.domain.model.institution.InstitutionType.SYSTEM_OPERATOR;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

@SpringJUnitWebConfig(QuestionnaireAccessTest.Config.class)
@MockitoBean(types = RefreshTokenRepository.class)
class QuestionnaireAccessTest {
    private static final String ACTOR = "testActor";
    private static final String QUESTIONNAIRE = "/api/journal/13/questionnaire";
    private static final String REPORT = QUESTIONNAIRE + "/report";
    private static final String YEARS = "/api/questionnaires/years";
    private static final String AGGREGATE_REPORT = "/api/reports/questionnaires/2024";
    private static final String ALLOWED_IP = "192.0.2.10";

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @Import({SecurityConfig.class, SpringSecurityCurrentActorProvider.class, JournalAuthorization.class,
            IpAccessEnforcementFilter.class, QuestionnaireController.class, QuestionnaireReportController.class})
    static class Config {
    }

    @Autowired private WebApplicationContext context;
    @Autowired private FilterChainProxy security;
    @MockitoBean private JwtAuthFilter jwt;
    @MockitoBean private LoginSessionActivityFilter activity;
    @MockitoBean private LoginSessionService sessions;
    @MockitoBean private InstitutionIpMatcherService ipMatcher;
    @MockitoBean private ClientRequestMetadataResolutionService metadata;
    @MockitoBean private InstitutionMembershipSpringDataRepository memberships;
    @MockitoBean private QuestionnaireService questionnaires;
    @MockitoBean private QuestionnaireReportFileService aggregateReports;

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
        doAnswer(invocation -> {
            invocation.<FilterChain>getArgument(2).doFilter(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(activity).doFilter(any(ServletRequest.class), any(ServletResponse.class), any(FilterChain.class));
        when(sessions.isActive(42L)).thenReturn(true);
        when(metadata.resolve(any())).thenAnswer(invocation -> {
            ClientRequestMetadataInput request = invocation.getArgument(0);
            return new ClientRequestMetadata(request.remoteAddress(), "JUnit");
        });
        mvc = webAppContextSetup(context).addFilters(security).build();
    }

    @Test
    void deniesGuestsAndUsersWithoutCatalogPermissions() throws Exception {
        var operator = user(SYSTEM_OPERATOR, INSTITUTION_ADMIN);
        for (var request : catalogRequests()) {
            mvc.perform(request).andExpect(status().isUnauthorized());
            mvc.perform(request.requestAttr(ACTOR, operator)).andExpect(status().isForbidden());
        }
        var pending = user(RESEARCH_UNIT, INSTITUTION_TO_CONFIRM);
        for (var request : catalogRequests()) {
            mvc.perform(request.requestAttr(ACTOR, pending)).andExpect(status().isForbidden());
        }
        verifyNoInteractions(questionnaires, aggregateReports);
    }

    @ParameterizedTest
    @EnumSource(value = InstitutionRole.class, names = {"INSTITUTION_VIEWER", "INSTITUTION_USER", "INSTITUTION_ADMIN"})
    void allowsResearchUnitCatalogRoles(InstitutionRole role) throws Exception {
        stubCatalogData();
        var actor = user(RESEARCH_UNIT, role);
        for (var request : catalogRequests()) {
            mvc.perform(request.requestAttr(ACTOR, actor)).andExpect(status().isOk());
        }
    }

    @Test
    void allowsInstitutionSessionsFromTheAuthorizedNetwork() throws Exception {
        stubCatalogData();
        var actor = institutionActor();
        when(ipMatcher.matchesInstitution(3L, ALLOWED_IP)).thenReturn(true);
        for (var request : catalogRequests()) {
            mvc.perform(request.requestAttr(ACTOR, actor).with(req -> {
                req.setRemoteAddr(ALLOWED_IP);
                return req;
            })).andExpect(status().isOk());
        }
    }

    @Test
    void deniesInstitutionSessionsFromOutsideTheAuthorizedNetwork() throws Exception {
        var actor = institutionActor();
        for (var request : catalogRequests()) {
            mvc.perform(request.requestAttr(ACTOR, actor))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("IP_ACCESS_DENIED"));
        }
        verifyNoInteractions(questionnaires, aggregateReports);
    }

    private List<MockHttpServletRequestBuilder> catalogRequests() {
        return List.of(get(QUESTIONNAIRE), get(REPORT), get(YEARS), get(AGGREGATE_REPORT + "/availability"),
                get(AGGREGATE_REPORT + "/pl"), get(AGGREGATE_REPORT + "/en"));
    }

    private void stubCatalogData() {
        when(questionnaires.findCurrentQuestionnaire(13L)).thenReturn(Optional.of(new QuestionnaireView()));
        when(questionnaires.generateCurrentQuestionnaireReport(13L, "pl"))
                .thenReturn(Optional.of(new SurveyReportResult(new byte[]{1}, 2024, "pl", "survey.xls")));
        when(questionnaires.findAvailableYears()).thenReturn(List.of(2024));
        when(aggregateReports.availability()).thenReturn(new QuestionnaireReportAvailabilityDto(true, true));
        for (var language : QuestionnaireReportLanguage.values()) {
            var file = new QuestionnaireReportFile(new ByteArrayResource(new byte[]{2}), 1,
                    "questionnaire-report-2024-" + language.code() + ".xlsx");
            when(aggregateReports.findReport(language)).thenReturn(Optional.of(file));
        }
    }

    private Authentication user(InstitutionType type, InstitutionRole role) {
        var institution = new Institution();
        institution.setId(3L);
        var user = new AppUser();
        user.setId(5L);
        var membership = new InstitutionMembership();
        membership.setInstitution(institution);
        membership.setUser(user);
        membership.setRole(role);
        membership.setLoginAllowedFromAnyIp(true);
        when(memberships.findById(7L)).thenReturn(Optional.of(membership));
        var principal = UserPrincipal.builder()
                .userId(5L).institutionId(3L).membershipId(7L).loginSessionId(42L)
                .institutionType(type).institutionRole(role)
                .build();
        return new TestingAuthenticationToken(principal, null, "USER");
    }

    private Authentication institutionActor() {
        var principal = new InstitutionPrincipal(3L, "Research Unit", RESEARCH_UNIT, INSTITUTION_VIEWER,
                "Research Unit", 42L);
        return new TestingAuthenticationToken(principal, null, "INSTITUTION_VIEWER");
    }
}
