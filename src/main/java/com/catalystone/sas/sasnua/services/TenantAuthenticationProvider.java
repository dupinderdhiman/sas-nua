package com.catalystone.sas.sasnua.services;

import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.function.Consumer;

public class TenantAuthenticationProvider implements AuthenticationProvider {

    private final TenantService tenantService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final TenantAuthService tenantAuthService;

    Logger log = org.slf4j.LoggerFactory.getLogger(TenantAuthenticationProvider.class);

    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();

    public TenantAuthenticationProvider(TenantService tenantService, RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService, TenantAuthService tenantAuthService) {
        this.tenantService = tenantService;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
        this.tenantAuthService = tenantAuthService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken auth =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        Authentication userAuth;

        /*String tenantAuthReqId = (String) auth.getAdditionalParameters().get("tenantAuthReqId");
        if(Objects.isNull(tenantAuthReqId)) {
            log.info("Tenant Authentication is required, so fallback to exception handler and redirect to tenant's URL");
            return auth;
        }
        else {
            userAuth = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());
        }*/

        userAuth = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());



        String codeChallenge = (String) auth.getAdditionalParameters().get("code_challenge");
        String codeChallengeMethod = (String) auth.getAdditionalParameters().get("code_challenge_method");

        var additionalParams = new HashMap<String, Object>(auth.getAdditionalParameters());
        additionalParams.put(Principal.class.getName(), userAuth);
        additionalParams.put("code_challenge", codeChallenge);
        additionalParams.put("code_challenge_method", codeChallengeMethod);



        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                auth.getAuthorizationUri(),
                auth.getClientId(),
                (Authentication) auth.getPrincipal(),
                auth.getRedirectUri(),
                auth.getState(),
                auth.getScopes(),
                additionalParams
        );



/*
        String clientId = auth.getClientId();


        String tenantId = (String) auth.getAdditionalParameters().get("tenant_id");
        String tenantUrl = (String) auth.getAdditionalParameters().get("tenant_url");

        String codeChallenge = (String) auth.getAdditionalParameters().get("code_challenge");
        String codeChallengeMethod = (String) auth.getAdditionalParameters().get("code_challenge_method");
        //String clientSecret = (String) auth.getAdditionalParameters().get("client_secret");
        // Here, you would typically redirect to the tenant's authentication page

        // For this example, we'll simulate successful authentication

        String jwtToken = tenantService.authenticateWithTenant(tenantUrl, tenantId);

        if (jwtToken != null) {
            // Store the JWT auth for later use
            tenantService.storeJwtToken(clientId, jwtToken);

            Authentication userAuth = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());

            // Return a new authenticated auth
            //SecurityContextHolder.getContext().setAuthentication(userAuth);

            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("authorization-code", Instant.now(), Instant.now().plus(60, ChronoUnit.MINUTES));

            OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(auth.getAuthorizationUri())
                    .clientId(clientId)
                    .redirectUri(auth.getRedirectUri())
                    .scopes(auth.getScopes())
                    .state(auth.getState())
                    .additionalParameters(auth.getAdditionalParameters())
                    .build();

            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(
                            Objects.requireNonNull(registeredClientRepository.findByClientId(clientId)))
                    .principalName("hrg")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(auth.getScopes())
                    .token(authorizationCode)
                    .attribute("tenant_id", tenantId)
                    .attribute("tenant_url", tenantUrl)
                    .attribute("code_challenge", codeChallenge)
                    .attribute("code_challenge_method", codeChallengeMethod)
                    //.attribute("client_secret", clientSecret)
                    .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                    .attribute(Principal.class.getName(), userAuth);

   *//*         RegisteredClient registeredClient = this.registeredClientRepository
                    .findByClientId(clientId);
            OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder = OAuth2AuthorizationCodeRequestAuthenticationContext
                    .with(auth)
                    .registeredClient(registeredClient);
            this.authenticationValidator.accept(authenticationContextBuilder.build());*//*



            //authenticationContextBuilder.authorizationRequest(authorizationRequest);




            authorizationService.save(authorizationBuilder.build());


            return new OAuth2AuthorizationCodeRequestAuthenticationToken(auth.getAuthorizationUri(),
                                                                         auth.getClientId(),
                                                                         userAuth,
                                                                         authorizationCode,
                                                                         auth.getRedirectUri(),
                                                                         auth.getState(),
                                                                         auth.getScopes());

        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);*/
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

}