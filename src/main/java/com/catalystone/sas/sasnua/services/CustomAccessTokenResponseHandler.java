package com.catalystone.sas.sasnua.services;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Objects;

public class CustomAccessTokenResponseHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizationCodeRequestAuthenticationToken accessToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        var authorizationCode = accessToken.getAuthorizationCode();
        var expiresIn = Objects.requireNonNull(Objects.requireNonNull(accessToken.getAuthorizationCode()).getExpiresAt()).toEpochMilli();
        assert authorizationCode != null;

        OAuth2AccessTokenResponse.Builder builder =
                OAuth2AccessTokenResponse.withToken(authorizationCode.getTokenValue()).tokenType(
                        OAuth2AccessToken.TokenType.BEARER).expiresIn(expiresIn).scopes(accessToken.getScopes());

        OAuth2AccessTokenResponse accessTokenResponse = builder.build();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        new OAuth2AccessTokenResponseHttpMessageConverter().write(accessTokenResponse, null, httpResponse);
    }
}



/*
OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

OAuth2AccessTokenResponse.Builder builder =
        OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
        builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        if (refreshToken != null) {
        builder.refreshToken(refreshToken.getTokenValue());
        }
        if (!CollectionUtils.isEmpty(additionalParameters)) {
        builder.additionalParameters(additionalParameters);
        }
OAuth2AccessTokenResponse accessTokenResponse = builder.build();
ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);*/
