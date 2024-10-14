package com.catalystone.sas.sasnua.services;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;


public class TenantAuthenticationProvider2 implements AuthenticationProvider {

    private final TenantService tenantService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;


    private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();
    private Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationConsentRequired = TenantAuthenticationProvider2::isAuthorizationConsentRequired;

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
    private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder());

    private final Log logger = LogFactory.getLog(getClass());



    public TenantAuthenticationProvider2(TenantService tenantService, RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
        this.tenantService = tenantService;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken token =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        String tenantUrl = (String) token.getAdditionalParameters().get("tenant_url");
        String tenantId = (String) token.getAdditionalParameters().get("tenant_id");

        // Here, you would typically redirect to the tenant's authentication page

        // For this example, we'll simulate successful authentication

        String jwtToken = tenantService.authenticateWithTenant(tenantUrl, tenantId);

        if (jwtToken != null) {
            // Store the JWT token for later use
            tenantService.storeJwtToken(token.getClientId(), jwtToken);

            Authentication authenticationToken = new UsernamePasswordAuthenticationToken(jwtToken, null, Collections.emptyList());

            // Return a new authenticated token
            //SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            authenticationToken = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    token.getAuthorizationUri(),
                    token.getClientId(),
                    authenticationToken,
                    token.getRedirectUri(),
                    token.getState(),
                    token.getScopes(),
                    token.getAdditionalParameters());

            authenticateFurther(authenticationToken);
            //OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("authorization-code", Instant.now(), Instant.now().plus(60,ChronoUnit.MINUTES));
            /*return
                    ;*/
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }


    public Authentication authenticateFurther(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(authorizationCodeRequestAuthentication.getClientId());
        if (registeredClient == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
                       authorizationCodeRequestAuthentication, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder = OAuth2AuthorizationCodeRequestAuthenticationContext
                .with(authorizationCodeRequestAuthentication)
                .registeredClient(registeredClient);
        this.authenticationValidator.accept(authenticationContextBuilder.build());

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format(
                        "Invalid request: requested grant_type is not allowed" + " for registered client '%s'",
                        registeredClient.getId()));
            }
            throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
                       authorizationCodeRequestAuthentication, registeredClient);
        }

        // code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
        String codeChallenge = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
                .get(PkceParameterNames.CODE_CHALLENGE);
        if (StringUtils.hasText(codeChallenge)) {
            String codeChallengeMethod = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
                    .get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
                throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
                           authorizationCodeRequestAuthentication, registeredClient, null);
            }
        }
        else if (registeredClient.getClientSettings().isRequireProofKey()) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
                       authorizationCodeRequestAuthentication, registeredClient, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated authorization code request parameters");
        }

        // ---------------
        // The request is valid - ensure the resource owner is authenticated
        // ---------------

        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Did not authenticate authorization code request since principal not authenticated");
            }
            // Return the authorization request as-is where isAuthenticated() is false
            return authorizationCodeRequestAuthentication;
        }

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
                .clientId(registeredClient.getClientId())
                .redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
                .scopes(authorizationCodeRequestAuthentication.getScopes())
                .state(authorizationCodeRequestAuthentication.getState())
                .additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
                .build();
        authenticationContextBuilder.authorizationRequest(authorizationRequest);

        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService
                .findById(registeredClient.getId(), principal.getName());
        if (currentAuthorizationConsent != null) {
            authenticationContextBuilder.authorizationConsent(currentAuthorizationConsent);
        }

        if (this.authorizationConsentRequired.test(authenticationContextBuilder.build())) {
            String state = DEFAULT_STATE_GENERATOR.generateKey();
            OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                    .attribute(OAuth2ParameterNames.STATE, state)
                    .build();

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Generated authorization consent state");
            }

            this.authorizationService.save(authorization);

            Set<String> currentAuthorizedScopes = (currentAuthorizationConsent != null)
                    ? currentAuthorizationConsent.getScopes() : null;

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Saved authorization");
            }

            return new OAuth2AuthorizationConsentAuthenticationToken(authorizationRequest.getAuthorizationUri(),
                                                                     registeredClient.getClientId(), principal, state, currentAuthorizedScopes, null);
        }

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(authorizationCodeRequestAuthentication,
                                                                              registeredClient, null, authorizationRequest.getScopes());
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                                                "The token generator failed to generate the authorization code.", ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated authorization code");
        }

        OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
                .authorizedScopes(authorizationRequest.getScopes())
                .token(authorizationCode)
                .build();
        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        String redirectUri = authorizationRequest.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated authorization code request");
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
                                                                     registeredClient.getClientId(), principal, authorizationCode, redirectUri,
                                                                     authorizationRequest.getState(), authorizationRequest.getScopes());
    }

    /**
     * Sets the {@link OAuth2TokenGenerator} that generates the
     * {@link OAuth2AuthorizationCode}.
     * @param authorizationCodeGenerator the {@link OAuth2TokenGenerator} that generates
     * the {@link OAuth2AuthorizationCode}
     * @since 0.2.3
     */
    public void setAuthorizationCodeGenerator(
            OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
        Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
        this.authorizationCodeGenerator = authorizationCodeGenerator;
    }

    /**
     * Sets the {@code Consumer} providing access to the
     * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
     * validating specific OAuth 2.0 Authorization Request parameters associated in the
     * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}. The default
     * authentication validator is
     * {@link OAuth2AuthorizationCodeRequestAuthenticationValidator}.
     *
     * <p>
     * <b>NOTE:</b> The authentication validator MUST throw
     * {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
     * @param authenticationValidator the {@code Consumer} providing access to the
     * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
     * validating specific OAuth 2.0 Authorization Request parameters
     * @since 0.4.0
     */
    public void setAuthenticationValidator(
            Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
        Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
        this.authenticationValidator = authenticationValidator;
    }

    /**
     * Sets the {@code Predicate} used to determine if authorization consent is required.
     *
     * <p>
     * The {@link OAuth2AuthorizationCodeRequestAuthenticationContext} gives the predicate
     * access to the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}, as well
     * as, the following context attributes:
     * <ul>
     * <li>The {@link RegisteredClient} associated with the authorization request.</li>
     * <li>The {@link OAuth2AuthorizationRequest} containing the authorization request
     * parameters.</li>
     * <li>The {@link OAuth2AuthorizationConsent} previously granted to the
     * {@link RegisteredClient}, or {@code null} if not available.</li>
     * </ul>
     * @param authorizationConsentRequired the {@code Predicate} used to determine if
     * authorization consent is required
     * @since 1.3
     */
    public void setAuthorizationConsentRequired(
            Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationConsentRequired) {
        Assert.notNull(authorizationConsentRequired, "authorizationConsentRequired cannot be null");
        this.authorizationConsentRequired = authorizationConsentRequired;
    }

    private static boolean isAuthorizationConsentRequired(
            OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
        if (!authenticationContext.getRegisteredClient().getClientSettings().isRequireAuthorizationConsent()) {
            return false;
        }
        // 'openid' scope does not require consent
        if (authenticationContext.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)
                && authenticationContext.getAuthorizationRequest().getScopes().size() == 1) {
            return false;
        }

        if (authenticationContext.getAuthorizationConsent() != null && authenticationContext.getAuthorizationConsent()
                .getScopes()
                .containsAll(authenticationContext.getAuthorizationRequest().getScopes())) {
            return false;
        }

        return true;
    }

    private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient,
                                                                    Authentication principal, OAuth2AuthorizationRequest authorizationRequest) {
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
    }

    private static OAuth2TokenContext createAuthorizationCodeTokenContext(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationCodeRequestAuthentication);
        // @formatter:on

        if (authorization != null) {
            tokenContextBuilder.authorization(authorization);
        }

        return tokenContextBuilder.build();
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
                && principal.isAuthenticated();
    }

    private static void throwError(String errorCode, String parameterName,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredClient registeredClient) {
        throwError(errorCode, parameterName, ERROR_URI, authorizationCodeRequestAuthentication, registeredClient, null);
    }

    private static void throwError(String errorCode, String parameterName, String errorUri,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient,
                   authorizationRequest);
    }

    private static void throwError(OAuth2Error error, String parameterName,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

        String redirectUri = resolveRedirectUri(authorizationCodeRequestAuthentication, authorizationRequest,
                                                registeredClient);
        if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
                && (parameterName.equals(OAuth2ParameterNames.CLIENT_ID)
                || parameterName.equals(OAuth2ParameterNames.STATE))) {
            redirectUri = null; // Prevent redirects
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                authorizationCodeRequestAuthentication.getAuthorizationUri(),
                authorizationCodeRequestAuthentication.getClientId(),
                (Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
                authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
                authorizationCodeRequestAuthentication.getAdditionalParameters());

        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
                                                                        authorizationCodeRequestAuthenticationResult);
    }

    private static String resolveRedirectUri(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {

        if (authorizationCodeRequestAuthentication != null
                && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            return authorizationCodeRequestAuthentication.getRedirectUri();
        }
        if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredClient != null) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }

    class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

        private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(
                Base64.getUrlEncoder().withoutPadding(), 96);

        @Nullable
        @Override
        public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
            if (context.getTokenType() == null || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt
                    .plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
            return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
        }

    }

}
