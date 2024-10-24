package com.catalystone.sas.sasnua.config;

import com.catalystone.sas.sasnua.reqconverter.AddTenantDetailsInRequest;
import com.catalystone.sas.sasnua.services.TenantAuthService;
import com.catalystone.sas.sasnua.services.TenantAuthenticationEntryEndpoint;
import com.catalystone.sas.sasnua.services.TenantService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
@EnableWebSecurity
public class SecurityConfig {

    private final TenantService tenantService;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final RegisteredClientRepository registeredClientRepository;
    private final TenantAuthService tenantAuthService;

    public SecurityConfig(TenantService tenantService,
                          OAuth2AuthorizationService authorizationService,
                          OAuth2AuthorizationConsentService authorizationConsentService,
                          RegisteredClientRepository registeredClientRepository, TenantAuthService tenantAuthService) {
        this.tenantService = tenantService;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
        this.registeredClientRepository = registeredClientRepository;
        this.tenantAuthService = tenantAuthService;
    }




    @Bean @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        var authorizationServerConfig = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
        .authorizationEndpoint(authorizationEndpoint ->
                authorizationEndpoint
                        .authorizationRequestConverters(c -> c.add(0, new AddTenantDetailsInRequest(tenantService, tenantAuthService)))
                        .consentPage("/oauth2/v1/authorize")
        );

        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new TenantAuthenticationEntryEndpoint(tenantService, tenantAuthService),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML, MediaType.APPLICATION_JSON)
                ))
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfig.getEndpointsMatcher()));

        http.headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer
                .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                        .includeSubDomains(false)
                        .preload(true)
                        .requestMatcher(AnyRequestMatcher.INSTANCE)));
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();

        /*http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer,
                      authorizationServer -> authorizationServer
                              .oidc(Customizer.withDefaults())
                              .authorizationEndpoint(authorizationEndpoint ->
                                                             authorizationEndpoint
                                                                     .authorizationRequestConverters(c -> {c.add(0, new AddTenantDetailsInRequest(tenantService, tenantAuthService));})
                                                                     *//*.authenticationProviders(ap -> {
                                                                                  ap.add(0, new TenantAuthenticationProvider(tenantService,
                                                                                                                             registeredClientRepository,
                                                                                                                             authorizationService,
                                                                                                                             authorizationConsentService,
                                                                                                                             tenantAuthService));
                                                                     })*//*
                                                                     .consentPage("/oauth2/v1/authorize"))
                ).exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new TenantAuthenticationEntryEndpoint(tenantService, tenantAuthService),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        ))
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);*/
 /*       OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
                .authorizationEndpoint(oAuth2AuthorizationEndpointConfigurer -> oAuth2AuthorizationEndpointConfigurer
                        .authorizationRequestConverters(authorizationRequestConverters -> {
                            authorizationRequestConverters.add(0, new AddTenantDetailsInRequest(tenantService, tenantAuthService));
                        })
                        .authenticationProviders(authenticationProviders -> {
                            authenticationProviders.add(0, new TenantAuthenticationProvider(tenantService,
                                                                                            registeredClientRepository,
                                                                                            authorizationService,
                                                                                            authorizationConsentService,
                                                                                            tenantAuthService));
                        }));
        // Enable OpenID Connect 1.0
        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new TenantAuthenticationEntryEndpoint(tenantService, tenantAuthService),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );*/


    }
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/tenant-authentication-callback/").authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll());
        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }



   /* @Bean @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

      *//*  OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer,
                      authorizationServer -> authorizationServer.authorizationEndpoint(
                              authorizationEndpoint -> authorizationEndpoint
                              .authorizationRequestConverters(c -> {
                                  c.add(0, new AddTenantDetailsInRequest(tenantService, tenantAuthService));
                                  //c.add(1, new RedirectToTenantForAuthentication(tenantAuthService));
                                  //c.add(2, new WaitForAuthenticationCallback());
                              })
//                            .authenticationProvider(new TenantAuthenticationProvider(tenantService, registeredClientRepository, authorizationService, authorizationConsentService))
                              .authenticationProviders(ap -> {
                                  ap.add(0, new TenantAuthenticationProvider(tenantService,
                                                                             registeredClientRepository,
                                                                             authorizationService,
                                                                             authorizationConsentService,
                                                                             tenantAuthService));
                              }).consentPage("/oauth2/v1/authorize"))

                );*//*

        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new TenantAuthenticationEntryEndpoint(tenantService, tenantAuthService),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        http.httpBasic(basic -> basic.authenticationEntryPoint(new TenantAuthenticationEntryEndpoint(tenantService, tenantAuthService)));
        //http.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }*/

//    private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
//        return (authenticationProviders) ->
//                authenticationProviders.forEach((authenticationProvider) -> {
//                    if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
//                        Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
//                                // Override default redirect_uri validator
//                                new CustomRedirectUriValidator()
//                                        // Reuse default scope validator
//                                        .andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);
//
//                        ((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider)
//                                .setAuthenticationValidator(authenticationValidator);
//                    }
//                });
//    }


//
//    static class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
//
//        @Override
//        public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
//            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
//                    authenticationContext.getAuthentication();
//            RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
//            String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();
//
//            // Use exact string matching when comparing client redirect URIs against pre-registered URIs
//            if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
//                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
//                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
//            }
//        }
//    }
    /*.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                        .accessTokenResponseClient(new CustomAccessTokenResponseHandler())
                                        .authorizationCodeGrant(authorizationCodeGrant -> authorizationCodeGrant
                                                .authorizationRequestRepository(new CustomAuthorizationRequestConverter(tenantService))
                                                .authorizationResponseHandler(new CustomAccessTokenResponseHandler()))
                                )*/

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}