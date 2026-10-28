package com.smapp.gateway.security;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationConverterTest {

    private final JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

    @Test
    void shouldExtractRolesWithRolePrefix() {
        Jwt jwt = new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "HS256"),
                Map.of(
                        "sub", "user@example.com",
                        "username", "testuser",
                        "roles", List.of("ROLE_USER", "ADMIN")
                )
        );

        AbstractAuthenticationToken auth = converter.convert(jwt).block();

        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("user@example.com");

        Collection<String> authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        assertThat(authorities).contains("ROLE_USER", "ROLE_ADMIN", "ADMIN");
    }

    @Test
    void shouldExtractFromScopeClaim() {
        Jwt jwt = new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "HS256"),
                Map.of(
                        "sub", "user@example.com",
                        "scope", "read write"
                )
        );

        AbstractAuthenticationToken auth = converter.convert(jwt).block();

        assertThat(auth).isNotNull();
        Collection<String> authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        assertThat(authorities).contains("read", "write");
    }
}
