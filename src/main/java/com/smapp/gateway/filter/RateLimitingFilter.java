package com.smapp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.smapp.gateway.config.GatewaySecurityProperties;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway GlobalFilter that protects APIs from DDoS and brute force attacks
 * using an in-memory sliding token window per IP address.
 */
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final GatewaySecurityProperties properties;
    private final ObjectMapper objectMapper;
    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    public RateLimitingFilter(GatewaySecurityProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!properties.getRateLimiter().isEnabled()) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        if (isExemptFromRateLimiting(path)) {
            return chain.filter(exchange);
        }

        String clientIp = resolveClientIp(request);

        boolean isAuthEndpoint = path.startsWith("/api/auth/login") || path.startsWith("/api/auth/register");
        int maxAllowed = isAuthEndpoint
                ? properties.getRateLimiter().getAuthRequestsPerMinute()
                : properties.getRateLimiter().getGeneralRequestsPerMinute();

        String key = (isAuthEndpoint ? "auth:" : "gen:") + clientIp;
        long currentMinute = System.currentTimeMillis() / 60000;

        RequestCounter counter = requestCounts.compute(key, (k, existing) -> {
            if (existing == null || existing.minute != currentMinute) {
                return new RequestCounter(currentMinute, new AtomicInteger(1));
            }
            existing.count.incrementAndGet();
            return existing;
        });

        int currentCount = counter.count.get();
        int remaining = Math.max(0, maxAllowed - currentCount);

        // Periodically prune stale entries if map grows large
        if (requestCounts.size() > 5000) {
            requestCounts.entrySet().removeIf(entry -> entry.getValue().minute < currentMinute - 2);
        }

        if (currentCount > maxAllowed) {
            log.warn("Rate limit exceeded for IP: {} on path: {} (Count: {} / Max: {})",
                    clientIp, path, currentCount, maxAllowed);
            return handleRateLimitExceeded(exchange, maxAllowed);
        }

        // Add rate-limit headers to response
        exchange.getResponse().getHeaders().set("X-RateLimit-Limit", String.valueOf(maxAllowed));
        exchange.getResponse().getHeaders().set("X-RateLimit-Remaining", String.valueOf(remaining));

        return chain.filter(exchange);
    }

    private boolean isExemptFromRateLimiting(String path) {
        return path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")
                || path.startsWith("/webjars")
                || path.contains("/v3/api-docs")
                || path.startsWith("/actuator");
    }

    private String resolveClientIp(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress != null && remoteAddress.getAddress() != null) {
            return remoteAddress.getAddress().getHostAddress();
        }
        return "unknown";
    }

    private Mono<Void> handleRateLimitExceeded(ServerWebExchange exchange, int limit) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set("Retry-After", "60");
        response.getHeaders().set("X-RateLimit-Limit", String.valueOf(limit));
        response.getHeaders().set("X-RateLimit-Remaining", "0");

        Map<String, Object> errorAttributes = new LinkedHashMap<>();
        errorAttributes.put("timestamp", Instant.now().toString());
        errorAttributes.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        errorAttributes.put("error", "Too Many Requests");
        errorAttributes.put("message", "Rate limit exceeded. Please try again after 60 seconds.");
        errorAttributes.put("path", exchange.getRequest().getPath().value());

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(errorAttributes);
        } catch (Exception e) {
            bytes = "{\"status\":429,\"error\":\"Too Many Requests\"}".getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // Runs early before routing
        return -100;
    }

    private static class RequestCounter {
        final long minute;
        final AtomicInteger count;

        RequestCounter(long minute, AtomicInteger count) {
            this.minute = minute;
            this.count = count;
        }
    }
}
