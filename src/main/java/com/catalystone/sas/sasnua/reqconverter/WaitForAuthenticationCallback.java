package com.catalystone.sas.sasnua.reqconverter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Collections;

public class WaitForAuthenticationCallback implements AuthenticationConverter {
    private final AuthenticationConverter defaultConverter;

    public WaitForAuthenticationCallback() {
        this.defaultConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) defaultConverter.convert(request);

        Authentication userAuth = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                defaultAuthentication.getAuthorizationUri(),
                defaultAuthentication.getClientId(),
                userAuth,
                defaultAuthentication.getRedirectUri(),
                defaultAuthentication.getState(),
                defaultAuthentication.getScopes(),
                defaultAuthentication.getAdditionalParameters()
        );
    }
}
