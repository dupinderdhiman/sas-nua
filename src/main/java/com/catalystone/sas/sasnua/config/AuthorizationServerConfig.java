package com.catalystone.sas.sasnua.config;

import com.catalystone.sas.sasnua.reqconverter.CustomAuthorizationRequestConverter;
import com.catalystone.sas.sasnua.services.TenantAuthenticationProvider;
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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    private final TenantService tenantService;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final RegisteredClientRepository registeredClientRepository;

    public AuthorizationServerConfig(TenantService tenantService,
                                     OAuth2AuthorizationService authorizationService,
                                     OAuth2AuthorizationConsentService authorizationConsentService,
                                     RegisteredClientRepository registeredClientRepository) {
        this.tenantService = tenantService;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
        this.registeredClientRepository = registeredClientRepository;
    }


    @Bean @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer
                                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                                                   .authorizationRequestConverter(new CustomAuthorizationRequestConverter(tenantService))
                                                                    .authenticationProvider(new TenantAuthenticationProvider(tenantService, registeredClientRepository,
                                                                                                                             authorizationService,
                                                                                                                             authorizationConsentService))
                                                                   //.authorizationResponseHandler(new CustomAccessTokenResponseHandler())
                                                                   .consentPage("/oauth2/v1/authorize"))
                                /*.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                        .accessTokenResponseClient(new CustomAccessTokenResponseHandler())
                                        .authorizationCodeGrant(authorizationCodeGrant -> authorizationCodeGrant
                                                .authorizationRequestRepository(new CustomAuthorizationRequestConverter(tenantService))
                                                .authorizationResponseHandler(new CustomAccessTokenResponseHandler()))
                                )*/
                );

        http.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }


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