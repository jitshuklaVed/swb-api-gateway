package com.smapp.gateway.filter;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

class UserContextRelayFilterTest {

    private UserContextRelayFilter filter;

    @BeforeEach
    void setUp() {
        filter = new UserContextRelayFilter();
    }

    @Test
    void shouldStripSpoofedHeadersForAnonymousRequests() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/public")
                .header(UserContextRelayFilter.HEADER_USER_ID, "999")
                .header(UserContextRelayFilter.HEADER_USER_EMAIL, "fake@spoof.com")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mutatedExchange -> {
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_ID)).isNull();
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_EMAIL)).isNull();
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_CORRELATION_ID)).isNotBlank();
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();
    }

    @Test
    void shouldRelayUserContextWhenAuthenticated() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/users/me")
                .header(UserContextRelayFilter.HEADER_USER_ID, "spoofed-id")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "HS256"),
                Map.of(
                        "sub", "test@smapp.com",
                        "userId", 42L,
                        "username", "testuser",
                        "roles", List.of("ROLE_USER")
                )
        );
        JwtAuthenticationToken auth = new JwtAuthenticationToken(
                jwt,
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))
        );

        GatewayFilterChain chain = mutatedExchange -> {
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_ID))
                    .isEqualTo("42");
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_EMAIL))
                    .isEqualTo("test@smapp.com");
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_NAME))
                    .isEqualTo("testuser");
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_USER_ROLES))
                    .isEqualTo("ROLE_USER");
            assertThat(mutatedExchange.getRequest().getHeaders().getFirst(UserContextRelayFilter.HEADER_CORRELATION_ID))
                    .isNotBlank();
            return Mono.empty();
        };

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .block();
    }
}
