package com.catalystone.sas.sasnua.reqconverter;

import com.catalystone.sas.sasnua.services.TenantAuthService;
import com.catalystone.sas.sasnua.services.TenantService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AddTenantDetailsInRequest implements AuthenticationConverter {

    private final TenantService tenantService;
    private final TenantAuthService tenantAuthService;
    private final AuthenticationConverter defaultConverter;
    Logger log = org.slf4j.LoggerFactory.getLogger(AddTenantDetailsInRequest.class);

    public AddTenantDetailsInRequest(TenantService tenantService, TenantAuthService tenantAuthService) {
        this.tenantService = tenantService;
        this.tenantAuthService = tenantAuthService;
        this.defaultConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }


    @Override
    public Authentication convert(HttpServletRequest request) {
        OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) defaultConverter.convert(
                request);

        if (defaultAuthentication == null) {
            return null;
        }

        String clientId = defaultAuthentication.getClientId();
        String tenantId = tenantService.getTenantIdForClient(clientId);
        String tenantUrl = tenantService.getTenantUrlForId(tenantId);
        String tenantAuthReqId = (String) defaultAuthentication.getAdditionalParameters().get("tenantAuthReqId");

        log.info("AddTenantDetails tenantAuthReqId: {}", tenantAuthReqId);

        Map<String, Object> additionalParameters = new HashMap<>(defaultAuthentication.getAdditionalParameters());
        additionalParameters.put("tenant_url", tenantUrl);
        additionalParameters.put("tenant_id", tenantId);

/*
        String tenantAuthReqId = (String) defaultAuthentication.getAdditionalParameters().get("tenantAuthReqId");
        if(Objects.isNull(tenantAuthReqId)) {
            log.info("Tenant Authentication is required, so fallback to exception handler and redirect to tenant's URL");

            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                                                "The token generator failed to generate the authorization code.", ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
*/

/*        tenantAuthReqId = UUID.randomUUID().toString();
        tenantAuthService.saveAuthRequest(tenantAuthReqId, false, null, null);

        // Redirect to tenantUrl with tenantAuthReqId
        String redirectUrl = UriComponentsBuilder.fromUriString(tenantUrl)
                .queryParam("tenantAuthReqId", tenantAuthReqId)
                .build()
                .toUriString();

        sendRedirect(request, redirectUrl);
        checkAuthenticationStatus(tenantAuthReqId);*/

/*        // Once authenticated, retrieve UserId and JWT, and create OAuth2Authentication token
        Optional<AuthDetails> authDetails = tenantAuthService.getAuthDetailsByReqId(tenantAuthReqId);

        if (authDetails.isPresent()) {
        if (authDetails.isPresent()) {
            String userId =  "hrg"; // authDetails.get().getUserId();
            String jwt = "jwt" ; //authDetails.get().getJwt();

            Authentication userAuth = new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList());
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
        }*/

        //return null;

        if (Objects.isNull(tenantAuthReqId)) {
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(defaultAuthentication.getAuthorizationUri(),
                                                                         defaultAuthentication.getClientId(),
                                                                         (Authentication) defaultAuthentication.getPrincipal(),
                                                                         defaultAuthentication.getRedirectUri(),
                                                                         defaultAuthentication.getState(),
                                                                         defaultAuthentication.getScopes(),
                                                                         additionalParameters);
        }else {
            var auth = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());
            additionalParameters.put(Principal.class.getName(), auth);
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(defaultAuthentication.getAuthorizationUri(),
                                                                         defaultAuthentication.getClientId(),
                                                                         auth,
                                                                         defaultAuthentication.getRedirectUri(),
                                                                         defaultAuthentication.getState(),
                                                                         defaultAuthentication.getScopes(),
                                                                         additionalParameters);
        }

    }
    // Set the Authentication into the SecurityContextHolder


    // Simulates redirect to tenant's URL (open new window)
/*    private void sendRedirect(HttpServletRequest request, String redirectUrl) {
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
    }*/

}
