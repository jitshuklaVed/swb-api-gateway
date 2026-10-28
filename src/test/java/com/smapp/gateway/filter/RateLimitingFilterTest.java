package com.smapp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.smapp.gateway.config.GatewaySecurityProperties;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RateLimitingFilterTest {

    private GatewaySecurityProperties properties;
    private ObjectMapper objectMapper;
    private RateLimitingFilter filter;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        properties = new GatewaySecurityProperties();
        properties.getRateLimiter().setEnabled(true);
        properties.getRateLimiter().setAuthRequestsPerMinute(2);
        properties.getRateLimiter().setGeneralRequestsPerMinute(5);

        objectMapper = new ObjectMapper();
        filter = new RateLimitingFilter(properties, objectMapper);

        chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @Test
    void shouldAllowRequestsUnderThreshold() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/login")
                .remoteAddress(new InetSocketAddress("127.0.0.1", 8080))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isNull(); // Not rejected
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Limit")).isEqualTo("2");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isEqualTo("1");
    }

    @Test
    void shouldBlockRequestsExceedingThresholdWith429() {
        InetSocketAddress remoteAddress = new InetSocketAddress("192.168.1.100", 8080);

        for (int i = 0; i < 2; i++) {
            MockServerHttpRequest req = MockServerHttpRequest.post("/api/auth/login")
                    .remoteAddress(remoteAddress)
                    .build();
            MockServerWebExchange ex = MockServerWebExchange.from(req);
            filter.filter(ex, chain).block();
        }

        // 3rd request should trigger 429
        MockServerHttpRequest request3 = MockServerHttpRequest.post("/api/auth/login")
                .remoteAddress(remoteAddress)
                .build();
        MockServerWebExchange exchange3 = MockServerWebExchange.from(request3);

        filter.filter(exchange3, chain).block();

        assertThat(exchange3.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange3.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("60");
    }
}
