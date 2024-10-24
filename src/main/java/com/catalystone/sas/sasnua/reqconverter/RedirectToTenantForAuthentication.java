/*
package com.catalystone.sas.sasnua.reqconverter;

import com.catalystone.sas.sasnua.services.AuthDetails;
import com.catalystone.sas.sasnua.services.TenantAuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.*;

public class RedirectToTenantForAuthentication implements AuthenticationConverter {

    private final AuthenticationConverter defaultConverter;
    private final TenantAuthService tenantAuthService;

    public RedirectToTenantForAuthentication(TenantAuthService tenantAuthService) {
        this.tenantAuthService = tenantAuthService;
        this.defaultConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication =
            (OAuth2AuthorizationCodeRequestAuthenticationToken) defaultConverter.convert(request);

        String tenantUrl = request.getParameter("tenant_url");


        // Generate tenantAuthReqId (UUID) and store in the database
        String tenantAuthReqId = UUID.randomUUID().toString();
        tenantAuthService.saveAuthRequest(tenantAuthReqId, false, null, null);

        // Redirect to tenantUrl with tenantAuthReqId
        String redirectUrl = UriComponentsBuilder.fromUriString(tenantUrl)
                .queryParam("tenantAuthReqId", tenantAuthReqId)
                .build()
                .toUriString();

        sendRedirect(request, redirectUrl);
        checkAuthenticationStatus(tenantAuthReqId);

        // Once authenticated, retrieve UserId and JWT, and create OAuth2Authentication token
        Optional<AuthDetails> authDetails = tenantAuthService.getAuthDetailsByReqId(tenantAuthReqId);

        if (authDetails.isPresent()) {
            String userId =  "hrg"; // authDetails.get().getUserId();
            String jwt = "jwt" ; //authDetails.get().getJwt();

            Authentication userAuth = new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList());
            Map<String, Object> additionalParameters = new HashMap<>(defaultAuthentication.getAdditionalParameters());
            additionalParameters.put("jwt", jwt);

            var authToken = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    defaultAuthentication.getAuthorizationUri(),
                    defaultAuthentication.getClientId(),
                    userAuth,
                    defaultAuthentication.getRedirectUri(),
                    defaultAuthentication.getState(),
                    defaultAuthentication.getScopes(),
                    additionalParameters);

            // Delete the row after completion
            tenantAuthService.deleteAuthRequest(tenantAuthReqId);

            return authToken;
        }

        return null;
    }


    // Simulates redirect to tenant's URL (open new window)
    private void sendRedirect(HttpServletRequest request, String redirectUrl) {
        try {
            request.getRequestDispatcher(redirectUrl).forward(request, null);
        } catch (Exception e) {
            throw new RuntimeException("Error in redirecting to tenant's URL", e);
        }
    }

    // Polls the database to check the authentication status for the reqId
    private void checkAuthenticationStatus(String tenantAuthReqId) {
        boolean isAuthenticated = false;
        int i = 0;
        while (!isAuthenticated) {
            try {
                Thread.sleep(Duration.ofSeconds(1).toMillis());
                i++;
            } catch (InterruptedException e) {
                throw new RuntimeException("Error in sleep during polling", e);
            }

            if( i >= 10) {
                isAuthenticated = true;
            }
            else
                isAuthenticated = tenantAuthService.isAuthenticated(tenantAuthReqId);
        }
    }
}
*/
