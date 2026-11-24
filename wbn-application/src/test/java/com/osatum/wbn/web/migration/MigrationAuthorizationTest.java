package com.osatum.wbn.web.migration;

import com.osatum.wbn.application.system.authorization.SystemAuthorization;
import com.osatum.wbn.domain.model.institution.InstitutionRole;
import com.osatum.wbn.domain.model.institution.InstitutionType;
import com.osatum.wbn.infrastructure.security.IpAccessEnforcementFilter;
import com.osatum.wbn.infrastructure.security.JwtAuthFilter;
import com.osatum.wbn.infrastructure.security.LoginSessionActivityFilter;
import com.osatum.wbn.infrastructure.security.SecurityConfig;
import com.osatum.wbn.infrastructure.security.SpringSecurityCurrentActorProvider;
import com.osatum.wbn.infrastructure.security.principal.UserPrincipal;
import com.osatum.wbn.migration.dto.MigrationImportStatusDto;
import com.osatum.wbn.migration.service.MigrationImportRunnerService;
import com.osatum.wbn.migration.service.QuestionnaireReportJobService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
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
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

@SpringJUnitWebConfig(MigrationAuthorizationTest.Config.class)
class MigrationAuthorizationTest {
    private static final String IMPORT = "/api/migration/import";
    private static final String REPORT = "/api/migration/questionnaire-report-2024";
    private static final String TEST_AUTHENTICATION = "testAuthentication";

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @Import({SecurityConfig.class, MigrationController.class, SystemAuthorization.class,
            SpringSecurityCurrentActorProvider.class})
    static class Config {
    }

    @Autowired private WebApplicationContext context;
    @Autowired private FilterChainProxy security;
    @MockitoBean private JwtAuthFilter jwt;
    @MockitoBean private IpAccessEnforcementFilter ip;
    @MockitoBean private LoginSessionActivityFilter activity;
    @MockitoBean private MigrationImportRunnerService imports;
    @MockitoBean private QuestionnaireReportJobService reports;

    private MockMvc mvc;

    @BeforeEach
    void setUp() throws Exception {
        doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            if (request.getAttribute(TEST_AUTHENTICATION) instanceof Authentication authentication) {
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
    void deniesAnonymousRequestsBeforeCallingJobServices() throws Exception {
        for (var request : migrationRequests()) {
            mvc.perform(request).andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
        }
        verifyNoInteractions(imports, reports);
    }

    @Test
    void requiresBothOperatorContextAndAdministratorRoleEvenWithGlobalAdminAuthority() throws Exception {
        for (var request : migrationRequests()) {
            mvc.perform(request.requestAttr(TEST_AUTHENTICATION, actor(RESEARCH_UNIT, INSTITUTION_ADMIN, "ADMIN")))
                    .andExpect(status().isForbidden());
            mvc.perform(request.requestAttr(TEST_AUTHENTICATION, actor(SYSTEM_OPERATOR, INSTITUTION_VIEWER, "ADMIN")))
                    .andExpect(status().isForbidden());
        }
        verifyNoInteractions(imports, reports);
    }

    @Test
    void allowsOperatorAdministratorToRunAndMonitorBothJobs() throws Exception {
        var jobStatus = new MigrationImportStatusDto();
        when(imports.startImport()).thenReturn(jobStatus);
        when(imports.status()).thenReturn(jobStatus);
        when(reports.startQuestionnaireReport2024()).thenReturn(jobStatus);
        when(reports.status()).thenReturn(jobStatus);

        for (var request : migrationRequests()) {
            mvc.perform(request.requestAttr(TEST_AUTHENTICATION, actor(SYSTEM_OPERATOR, INSTITUTION_ADMIN, "USER")))
                    .andExpect(status().isOk());
        }

        verify(imports).startImport();
        verify(imports).status();
        verify(reports).startQuestionnaireReport2024();
        verify(reports).status();
    }

    @Test
    void importCannotBeStartedWithGetEvenByOperatorAdministrator() throws Exception {
        mvc.perform(get(IMPORT).requestAttr(TEST_AUTHENTICATION, actor(SYSTEM_OPERATOR, INSTITUTION_ADMIN, "ADMIN")))
                .andExpect(status().isMethodNotAllowed());
        verifyNoInteractions(imports, reports);
    }

    private List<MockHttpServletRequestBuilder> migrationRequests() {
        return List.of(post(IMPORT), get(IMPORT + "/status"), post(REPORT), get(REPORT + "/status"));
    }

    private Authentication actor(InstitutionType type, InstitutionRole role, String authority) {
        var principal = UserPrincipal.builder()
                .userId(1L)
                .institutionId(2L)
                .institutionType(type)
                .institutionRole(role)
                .build();
        return new TestingAuthenticationToken(principal, null, authority);
    }
}
