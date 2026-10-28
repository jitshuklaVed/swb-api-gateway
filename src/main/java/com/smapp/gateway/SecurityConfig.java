package com.smapp.gateway;

import com.smapp.gateway.config.GatewaySecurityProperties;
import com.smapp.gateway.security.GatewayAccessDeniedHandler;
import com.smapp.gateway.security.GatewayAuthenticationEntryPoint;
import com.smapp.gateway.security.JwtAuthenticationConverter;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            GatewaySecurityProperties properties,
            ReactiveJwtDecoder jwtDecoder,
            JwtAuthenticationConverter jwtAuthenticationConverter,
            GatewayAuthenticationEntryPoint authenticationEntryPoint,
            GatewayAccessDeniedHandler accessDeniedHandler,
            CorsConfigurationSource corsConfigurationSource) {

        String[] publicPaths = properties.getPublicEndpoints().toArray(new String[0]);

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                        .xssProtection(xss -> xss.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK))
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                        .hsts(hsts -> hsts.includeSubdomains(true).maxAge(Duration.ofDays(365)))
                )
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers(publicPaths).permitAll()
                        .pathMatchers("/api/users/me/**").authenticated()
                        .pathMatchers(HttpMethod.GET, "/api/posts/**", "/api/reels/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/posts/reels/*/view", "/api/reels/*/views").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/friends/user/**", "/api/friends/count/**", "/api/friends/followers/**", "/api/friends/following/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/pages/**").permitAll()
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(GatewaySecurityProperties properties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(properties.getCors().getAllowedOrigins());
        config.setAllowedMethods(properties.getCors().getAllowedMethods());
        config.setAllowedHeaders(properties.getCors().getAllowedHeaders());
        config.setExposedHeaders(List.of(
                "Authorization",
                "X-Correlation-Id",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "Retry-After"
        ));
        config.setAllowCredentials(properties.getCors().isAllowCredentials());
        config.setMaxAge(properties.getCors().getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder(GatewaySecurityProperties properties) {
        String secret = properties.getJwt().getSecret();
        String neonJwksUri = properties.getJwt().getNeonAuth().getJwksUri();

        ReactiveJwtDecoder rsaDecoder = buildRsaDecoder(properties);

        var key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        var localHmacDecoder = NimbusReactiveJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        var neonDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(neonJwksUri).build();

        return token -> rsaDecoder.decode(token)
                .doOnError(e -> log.debug("RSA token decoding failed: {}, attempting HMAC / Neon Auth fallback", e.getMessage()))
                .onErrorResume(e1 -> localHmacDecoder.decode(token))
                .onErrorResume(e2 -> neonDecoder.decode(token));
    }

    private ReactiveJwtDecoder buildRsaDecoder(GatewaySecurityProperties properties) {
        String authServiceJwksUri = properties.getJwt().getRsa().getJwksUri();
        String rsaPublicKeyPem = properties.getJwt().getRsa().getPublicKey();

        if (rsaPublicKeyPem != null && !rsaPublicKeyPem.isBlank()) {
            try {
                var pubKey = parsePublicKey(rsaPublicKeyPem);
                log.info("Configured RSA ReactiveJwtDecoder with static RSA Public Key");
                return NimbusReactiveJwtDecoder.withPublicKey(pubKey).build();
            } catch (Exception e) {
                log.warn("Failed to parse configured RSA Public Key PEM ({}), falling back to JWKS URI", e.getMessage());
            }
        }
        log.info("Configured RSA ReactiveJwtDecoder with JWKS URI: {}", authServiceJwksUri);
        return NimbusReactiveJwtDecoder.withJwkSetUri(authServiceJwksUri).build();
    }

    private java.security.interfaces.RSAPublicKey parsePublicKey(String pem) throws Exception {
        String clean = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] bytes = java.util.Base64.getDecoder().decode(clean);
        var spec = new java.security.spec.X509EncodedKeySpec(bytes);
        return (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
