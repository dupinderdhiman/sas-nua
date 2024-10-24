package com.catalystone.sas.sasnua.services;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.UUID;

@Slf4j
public class TenantAuthenticationEntryEndpoint implements AuthenticationEntryPoint {

    private final TenantService tenantService;
    private final TenantAuthService tenantAuthService;
    private final AuthenticationConverter defaultConverter;


    public TenantAuthenticationEntryEndpoint(TenantService tenantService, TenantAuthService tenantAuthService) {
        this.tenantService = tenantService;
        this.tenantAuthService = tenantAuthService;
        this.defaultConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) defaultConverter.convert(request);

            if (defaultAuthentication == null) {
                return;
            }

            String clientId = defaultAuthentication.getClientId();
            String tenantId = tenantService.getTenantIdForClient(clientId);
            String tenantUrl = tenantService.getTenantUrlForId(tenantId);

        String tenantAuthReqId = UUID.randomUUID().toString();
        tenantAuthService.saveAuthRequest(tenantAuthReqId, false, null, null, defaultAuthentication);
        log.info("Redirected to tenantUrl: {}", tenantUrl);
        log.info("tenantAuthReqId: {}", tenantAuthReqId);


        // Redirect to tenantUrl with tenantAuthReqId
        // http://localhost:4200/auth?tenantAuthReqId=your-UUID
        String redirectUrl = UriComponentsBuilder.fromUriString(tenantUrl+"/auth?tenantAuthReqId="+tenantAuthReqId)
                .build()
                .toUriString();
        response.sendRedirect(redirectUrl);
    }
}
