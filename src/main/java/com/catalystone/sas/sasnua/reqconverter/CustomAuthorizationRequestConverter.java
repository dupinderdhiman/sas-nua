package com.catalystone.sas.sasnua.reqconverter;

import com.catalystone.sas.sasnua.services.TenantService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.HashMap;
import java.util.Map;

public class CustomAuthorizationRequestConverter implements AuthenticationConverter {

    private final TenantService tenantService;
    private final AuthenticationConverter defaultConverter;

    public CustomAuthorizationRequestConverter(TenantService tenantService) {
        this.tenantService = tenantService;
        this.defaultConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }


    @Override
    public Authentication convert(HttpServletRequest request) {
        OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) defaultConverter.convert(request);

        if (defaultAuthentication == null) {
            return null;
        }

        String clientId = defaultAuthentication.getClientId();
        String tenantId = tenantService.getTenantIdForClient(clientId);
        String tenantUrl = tenantService.getTenantUrlForId(tenantId);

        Map<String, Object> additionalParameters = new HashMap<>(defaultAuthentication.getAdditionalParameters());
        additionalParameters.put("tenant_url", tenantUrl);
        additionalParameters.put("tenant_id", tenantId);



        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                defaultAuthentication.getAuthorizationUri(),
                defaultAuthentication.getClientId(),
                (Authentication) defaultAuthentication.getPrincipal(),
                defaultAuthentication.getRedirectUri(),
                defaultAuthentication.getState(),
                defaultAuthentication.getScopes(),
                additionalParameters);
    }

    // Set the Authentication into the SecurityContextHolder


}
