package com.catalystone.sas.sasnua.services;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

@Getter @Setter
public class AuthDetails {
    private String reqId;
    private boolean isAuthenticated;
    private String userId;
    private String jwt;
    private OAuth2AuthorizationCodeRequestAuthenticationToken request;

    public AuthDetails(String reqId, boolean isAuthenticated, String userId, String jwt, OAuth2AuthorizationCodeRequestAuthenticationToken request) {
        this.reqId = reqId;
        this.isAuthenticated = isAuthenticated;
        this.userId = userId;
        this.jwt = jwt;
        this.request = request;
    }
}