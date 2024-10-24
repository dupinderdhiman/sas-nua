package com.catalystone.sas.sasnua.services;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TenantAuthService {
    // Simulating an in-memory database using ConcurrentHashMap for simplicity
    // In a real application, this would be replaced by JPA/Hibernate repository calls
    private final ConcurrentHashMap<String, AuthDetails> authRequestDatabase = new ConcurrentHashMap<>();

    // Save authentication request details
    public void saveAuthRequest(String reqId, boolean isAuthenticated, String userId, String jwt, OAuth2AuthorizationCodeRequestAuthenticationToken defaultAuthentication) {
        AuthDetails authDetails = new AuthDetails(reqId, isAuthenticated, userId, jwt, defaultAuthentication);
        authRequestDatabase.put(reqId, authDetails);
    }

    // Check if a request is authenticated by reqId
    public boolean isAuthenticated(String reqId) {
        AuthDetails authDetails = authRequestDatabase.get(reqId);
        return authDetails != null && authDetails.isAuthenticated();
    }

    // Get authentication details by reqId
    public Optional<AuthDetails> getAuthDetailsByReqId(String reqId) {
        return Optional.ofNullable(authRequestDatabase.get(reqId));
    }

    // Update authentication status and store JWT token and userId when callback is triggered
    public void updateAuthRequest(String reqId, String userId, String jwt) {
        AuthDetails authDetails = authRequestDatabase.get(reqId);
        if (authDetails != null) {
            authDetails.setAuthenticated(true);
            authDetails.setUserId(userId);
            authDetails.setJwt(jwt);
            authRequestDatabase.put(reqId, authDetails);
        }
    }

    // Delete authentication request after successful handling
    public void deleteAuthRequest(String reqId) {
        authRequestDatabase.remove(reqId);
    }
}
