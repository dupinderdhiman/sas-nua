package com.catalystone.sas.sasnua;


import com.catalystone.sas.sasnua.services.TenantAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/tenant-authentication-callback")
public class TenantAuthenticationCallback {

    @Autowired TenantAuthService tenantAuthService;

    @GetMapping("")
    public void handleTenantAuthenticationCallback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Extract tenantAuthReqId from request
        String tenantAuthReqId = request.getParameter("tenantAuthReqId");
        String authroization = request.getParameter("Authorization");

        var authReqDetails = tenantAuthService.getAuthDetailsByReqId(tenantAuthReqId).orElseThrow();

        var oAuth2Req = authReqDetails.getRequest();
        var userName = authroization.split(" ")[1];

        Map<String, Object> additionalParameters = new HashMap<>(oAuth2Req.getAdditionalParameters());
        additionalParameters.put("tenantAuthReqId", tenantAuthReqId);
        additionalParameters.put("username", userName);


        Authentication userAuth = new UsernamePasswordAuthenticationToken(userName, null, Collections.emptyList());
        var newOAuth2Req = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                oAuth2Req.getAuthorizationUri(),
                oAuth2Req.getClientId(),
                userAuth,
                oAuth2Req.getRedirectUri(),
                oAuth2Req.getState(),
                oAuth2Req.getScopes(),
                additionalParameters
        );

        // Redirect to the OAuth2 Authorization Server with the new OAuth2AuthorizationCodeRequestAuthenticationToken
        response.sendRedirect(buildOAuth2AuthorizeUri(newOAuth2Req));
    }

    public String buildOAuth2AuthorizeUri(OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        // Extract values from the OAuth2AuthorizationCodeRequestAuthenticationToken
        String clientId = token.getClientId();
        String redirectUri = token.getRedirectUri();
        String scope = String.join(" ", token.getScopes()); // Scopes are typically space-separated

        // Build the query string for redirect
        StringBuilder uriBuilder = new StringBuilder("/oauth2/authorize?");
        uriBuilder.append("response_type=").append(encodeValue("code"));
        uriBuilder.append("&client_id=").append(encodeValue(clientId));
        uriBuilder.append("&state=").append(encodeValue(token.getState()));
        uriBuilder.append("&scope=").append(encodeValue(scope));
        uriBuilder.append("&redirect_uri=").append(encodeValue(redirectUri));

        // Optionally add other parameters like 'state', 'code_challenge', 'code_challenge_method', etc.
        Map<String, Object> additionalParameters = token.getAdditionalParameters();
        additionalParameters.forEach((key, value) -> {
            uriBuilder.append("&").append(encodeValue(key)).append("=").append(encodeValue(value.toString()));
        });

        return uriBuilder.toString();
    }

    private String encodeValue(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Failed to encode parameter", e);
        }
    }
}
