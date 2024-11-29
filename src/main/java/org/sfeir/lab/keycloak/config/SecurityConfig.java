package org.sfeir.lab.keycloak.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true)
@EnableConfigurationProperties(IssuersProperties.class)
public class SecurityConfig {

    public static final String ADMIN = "admin";
    public static final String USER = "user";
    private final IssuersProperties issuersProperties;
    private final KeycloakJwtConverter keycloakJwtConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz ->
                authz.anyRequest().authenticated());

        http.sessionManagement(sess -> sess.sessionCreationPolicy(
                SessionCreationPolicy.STATELESS));

        http.oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(authenticationManagerResolver())
                );

        return http.build();
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();

        for (String issuer : issuersProperties.issuers()) {
            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
            jwtDecoder.setJwtValidator(getJwtOAuth2TokenValidator(issuer));

            JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
            provider.setJwtAuthenticationConverter(keycloakJwtConverter);
            authenticationManagers.put(issuer, provider::authenticate);
        }

        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    private static OAuth2TokenValidator<Jwt> getJwtOAuth2TokenValidator(final String issuer) {
        OAuth2TokenValidator<Jwt> jwtOAuth2TokenValidator = jwt -> {

            if (jwt == null) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "JWT algorithm not found.", null));
            }

            String algorithm = jwt.getHeaders().get("alg").toString();
            if (algorithm == null || algorithm.equalsIgnoreCase("none")) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid JWT algorithm", null));
            }

            return OAuth2TokenValidatorResult.success();
        };

        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuer);


        return new DelegatingOAuth2TokenValidator<>(defaultValidators, jwtOAuth2TokenValidator);
    }

}