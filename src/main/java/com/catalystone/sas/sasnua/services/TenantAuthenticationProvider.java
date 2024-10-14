package com.catalystone.sas.sasnua.services;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Objects;
import java.util.function.Consumer;

public class TenantAuthenticationProvider implements AuthenticationProvider {

    private final TenantService tenantService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();
    public TenantAuthenticationProvider(TenantService tenantService, RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
        this.tenantService = tenantService;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken token =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;


        String clientId = token.getClientId();

        String tenantId = (String) token.getAdditionalParameters().get("tenant_id");
        String tenantUrl = (String) token.getAdditionalParameters().get("tenant_url");

        String codeChallenge = (String) token.getAdditionalParameters().get("code_challenge");
        String codeChallengeMethod = (String) token.getAdditionalParameters().get("code_challenge_method");
        String clientSecret = (String) token.getAdditionalParameters().get("client_secret");
        // Here, you would typically redirect to the tenant's authentication page

        // For this example, we'll simulate successful authentication

        String jwtToken = tenantService.authenticateWithTenant(tenantUrl, tenantId);

        if (jwtToken != null) {
            // Store the JWT token for later use
            tenantService.storeJwtToken(clientId, jwtToken);

            Authentication authenticationToken = new UsernamePasswordAuthenticationToken("hrg", null, Collections.emptyList());

            // Return a new authenticated token
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("authorization-code", Instant.now(), Instant.now().plus(60, ChronoUnit.MINUTES));

            OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(token.getAuthorizationUri())
                    .clientId(clientId)
                    .redirectUri(token.getRedirectUri())
                    .scopes(token.getScopes())
                    .state(token.getState())
                    .additionalParameters(token.getAdditionalParameters())
                    .build();

            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(
                            Objects.requireNonNull(registeredClientRepository.findByClientId(clientId)))
                    .principalName("hrg")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(token.getScopes())
                    .token(authorizationCode)
                    .attribute("tenant_id", tenantId)
                    .attribute("tenant_url", tenantUrl)
                    .attribute("code_challenge", codeChallenge)
                    .attribute("code_challenge_method", codeChallengeMethod)
                    .attribute("client_secret", clientSecret)
                    .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                    .attribute(Principal.class.getName(), authenticationToken);

   /*         RegisteredClient registeredClient = this.registeredClientRepository
                    .findByClientId(clientId);
            OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder = OAuth2AuthorizationCodeRequestAuthenticationContext
                    .with(token)
                    .registeredClient(registeredClient);
            this.authenticationValidator.accept(authenticationContextBuilder.build());*/



            //authenticationContextBuilder.authorizationRequest(authorizationRequest);




            authorizationService.save(authorizationBuilder.build());


            return new OAuth2AuthorizationCodeRequestAuthenticationToken(token.getAuthorizationUri(),
                                                                         token.getClientId(),
                                                                         authenticationToken,
                                                                         authorizationCode,
                                                                         token.getRedirectUri(),
                                                                         token.getState(),
                                                                         token.getScopes());

        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

}