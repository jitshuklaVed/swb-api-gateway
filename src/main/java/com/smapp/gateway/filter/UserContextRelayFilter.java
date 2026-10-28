package com.smapp.gateway.filter;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway GlobalFilter that propagates sanitized authenticated user context downstream
 * and appends/relays an end-to-end tracing X-Correlation-Id header.
 */
@Component
public class UserContextRelayFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(UserContextRelayFilter.class);

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_EMAIL = "X-User-Email";
    public static final String HEADER_USER_NAME = "X-User-Username";
    public static final String HEADER_USER_ROLES = "X-User-Roles";
    public static final String HEADER_CORRELATION_ID = "X-Correlation-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 1. Maintain or generate Correlation ID
        String incomingCorrelationId = request.getHeaders().getFirst(HEADER_CORRELATION_ID);
        String correlationId = (incomingCorrelationId != null && !incomingCorrelationId.isBlank())
                ? incomingCorrelationId
                : UUID.randomUUID().toString();

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated())
                .map(auth -> buildAuthenticatedExchange(exchange, auth, correlationId))
                .defaultIfEmpty(buildAnonymousExchange(exchange, correlationId))
                .flatMap(mutatedExchange -> {
                    // Propagate correlation ID in downstream response
                    mutatedExchange.getResponse().getHeaders().set(HEADER_CORRELATION_ID, correlationId);
                    return chain.filter(mutatedExchange);
                });
    }

    private ServerWebExchange buildAuthenticatedExchange(
            ServerWebExchange exchange,
            Authentication auth,
            String correlationId) {

        ServerHttpRequest.Builder reqBuilder = exchange.getRequest().mutate();
        reqBuilder.header(HEADER_CORRELATION_ID, correlationId);

        // Sanitize incoming spoofed headers from untrusted external clients
        reqBuilder.headers(headers -> {
            headers.remove(HEADER_USER_ID);
            headers.remove(HEADER_USER_EMAIL);
            headers.remove(HEADER_USER_NAME);
            headers.remove(HEADER_USER_ROLES);
        });

        if (auth.getPrincipal() instanceof Jwt jwt) {
            Object userId = jwt.getClaim("userId");
            if (userId != null) {
                reqBuilder.header(HEADER_USER_ID, String.valueOf(userId));
            }

            String email = jwt.getSubject();
            if (email != null) {
                reqBuilder.header(HEADER_USER_EMAIL, email);
            }

            String username = jwt.getClaimAsString("username");
            if (username != null) {
                reqBuilder.header(HEADER_USER_NAME, username);
            }

            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null && !roles.isEmpty()) {
                reqBuilder.header(HEADER_USER_ROLES, String.join(",", roles));
            } else if (!auth.getAuthorities().isEmpty()) {
                String rolesJoined = auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(","));
                reqBuilder.header(HEADER_USER_ROLES, rolesJoined);
            }

            log.debug("Propagating user context: userId={}, username={}, correlationId={}",
                    userId, username, correlationId);
        } else if (auth.getName() != null) {
            reqBuilder.header(HEADER_USER_NAME, auth.getName());
        }

        return exchange.mutate().request(reqBuilder.build()).build();
    }

    private ServerWebExchange buildAnonymousExchange(ServerWebExchange exchange, String correlationId) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(HEADER_CORRELATION_ID, correlationId)
                .headers(headers -> {
                    headers.remove(HEADER_USER_ID);
                    headers.remove(HEADER_USER_EMAIL);
                    headers.remove(HEADER_USER_NAME);
                    headers.remove(HEADER_USER_ROLES);
                })
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
