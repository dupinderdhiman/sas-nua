package com.catalystone.sas.sasnua.services;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TenantService {

    private final Map<String, String> clientToTenantMap = new ConcurrentHashMap<>();
    private final Map<String, String> tenantIdToUrlMap = new ConcurrentHashMap<>();
    private final Map<String, String> storedJwtTokens = new ConcurrentHashMap<>();

    public TenantService() {
        // Initialize with some dummy data
        clientToTenantMap.put("client", "tenant1");
//        tenantIdToUrlMap.put("tenant1", "https://iamroutinedev1.devtest.catalystone.dev");
        tenantIdToUrlMap.put("tenant1", "http://localhost:4200");
    }

    public String getTenantIdForClient(String clientId) {
        return clientToTenantMap.get(clientId);
    }

    public String getTenantUrlForId(String tenantId) {
        return tenantIdToUrlMap.get(tenantId);
    }

    public String authenticateWithTenant(String tenantUrl, String tenantId) {
        // In a real implementation, this would redirect to the tenant's auth page
        // For this example, we'll just return a dummy JWT
        return "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoZW50aWNhdGlvbi5jYXRhbHlzdG9uZS5jb20iLCJleHAiOjE3Mjc0MjI5NzgsImlhdCI6MTcyNzQxOTM3OCwianRpIjoiNjU0MWEwMjMtNWRiZi00YmJmLWFlNDktMjEwYjBhNzhjZTk0Iiwic3ViIjoiYTBjNmQ4NzgtN2EyYy00ZDE3LTgyMzAtNTMyMjEzNjZkZTRjIiwiaHR0cHM6Ly93d3cuY2F0YWx5c3RvbmUuY29tL2NsYWltcy9wcmVmZXJyZWRfdXNlcm5hbWUiOiJocmciLCJ0ZW5hbnRfbmFtZSI6ImlhbXJvdXRpbmVkZXYxIiwiaHR0cHM6Ly93d3cuY2F0YWx5c3RvbmUuY29tL2NsYWltcy9hdXRoX3RpbWUiOjE3Mjc0MTkzNzgwNDYsImh0dHBzOi8vd3d3LmNhdGFseXN0b25lLmNvbS9jbGFpbXMvdXNlcl9lbWFpbF9pZCI6Im1hbWFya3Vzc2VuQGNhdGFseXN0b25lLmNvbSIsImh0dHBzOi8vd3d3LmNhdGFseXN0b25lLmNvbS9jbGFpbXMvcHJvZmlsZSI6ImZkMzk2NmJhLTBlMjQtNDI4NS04NTIxLTQxZDQyN2ZjYzM5OCIsInByb2ZpbGUiOiJmZDM5NjZiYS0wZTI0LTQyODUtODUyMS00MWQ0MjdmY2MzOTgiLCJodHRwczovL3d3dy5jYXRhbHlzdG9uZS5jb20vY2xhaW1zL2xvY2FsZSI6ImVuLUdCIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiaHJnIiwibG9jYWxlIjoiZW4tR0IiLCJ1c2VyX2VtYWlsX2lkIjoibWFtYXJrdXNzZW5AY2F0YWx5c3RvbmUuY29tIiwiYWF0IjoxNzI3NDE5Mzc4MDQ2LCJodHRwczovL3d3dy5jYXRhbHlzdG9uZS5jb20vY2xhaW1zL3RlbmFudF9uYW1lIjoiaWFtcm91dGluZWRldjEiLCJodHRwczovL3d3dy5jYXRhbHlzdG9uZS5jb20vY2xhaW1zL3RlbmFudCI6IjFhODcxNTM1LTYxZTItNTcyNi04YWU0LTM2NzgzZmZmYTIyYyIsInRlbmFudCI6IjFhODcxNTM1LTYxZTItNTcyNi04YWU0LTM2NzgzZmZmYTIyYyIsImh0dHBzOi8vd3d3LmNhdGFseXN0b25lLmNvbS9jbGFpbXMvc3ViX3R5cGUiOiJ1c2VyIn0.E6_qmq7LdeWlD4hCJPxxNsf3b37Hps-P3dMjDYSxl7hAOfqZBV-dVqNscKilO9gnTlGi319uqyzEe0b8fZtFlpQ9kKh5GOEZID4MGJqHPHpYfomABXQ3-DQRudzL3hrL_1DUKi1lcNjzfgJlDcnqzOshw1oH7Ri3XyqM6ixO7tw72OFYPJgnu5PjYmh796mxegC1_8IKJ-VnuIRAeTkuxJB7fSco8hWiqvcODqqZpoZ5jTw_fCHK5ISlJo0gXicFiskq0YjRgkmtGfBmNAGxR2FA_NxX7b3Xrh4OmMXTMH3WBS_egPvgxqJ3LeifLA4CdvEQUxHH41XgmqmE6yOIMw";
    }

    public void storeJwtToken(String clientId, String jwtToken) {
        storedJwtTokens.put(clientId, jwtToken);
    }

    public String getStoredJwtToken(String clientId) {
        return storedJwtTokens.get(clientId);
    }
}