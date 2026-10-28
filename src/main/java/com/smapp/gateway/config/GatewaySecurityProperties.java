package com.smapp.gateway.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security")
public class GatewaySecurityProperties {

    private Jwt jwt = new Jwt();
    private Cors cors = new Cors();
    private RateLimiter rateLimiter = new RateLimiter();
    private List<String> publicEndpoints = new ArrayList<>(List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/validate",
            "/api/media/view/**",
            "/neon-auth/**",
            "/actuator/health",
            "/actuator/info",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/webjars/**",
            "/auth-service/v3/api-docs/**",
            "/.well-known/jwks.json",
            "/api/auth/.well-known/jwks.json",
            "/api/auth/public-key"
    ));

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Cors getCors() {
        return cors;
    }

    public void setCors(Cors cors) {
        this.cors = cors;
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public void setRateLimiter(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    public List<String> getPublicEndpoints() {
        return publicEndpoints;
    }

    public void setPublicEndpoints(List<String> publicEndpoints) {
        this.publicEndpoints = publicEndpoints;
    }

    public static class Jwt {
        private String secret = "change-this-development-secret-key-32-bytes";
        private NeonAuth neonAuth = new NeonAuth();
        private Rsa rsa = new Rsa();

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public NeonAuth getNeonAuth() {
            return neonAuth;
        }

        public void setNeonAuth(NeonAuth neonAuth) {
            this.neonAuth = neonAuth;
        }

        public Rsa getRsa() {
            return rsa;
        }

        public void setRsa(Rsa rsa) {
            this.rsa = rsa;
        }

        public static class Rsa {
            private String jwksUri = "http://localhost:8081/.well-known/jwks.json";
            private String publicKey = "";

            public String getJwksUri() {
                return jwksUri;
            }

            public void setJwksUri(String jwksUri) {
                this.jwksUri = jwksUri;
            }

            public String getPublicKey() {
                return publicKey;
            }

            public void setPublicKey(String publicKey) {
                this.publicKey = publicKey;
            }
        }

        public static class NeonAuth {
            private String jwksUri = "https://ep-odd-wildflower-b41gmcrb.neonauth.c-6.us-east-2.aws.neon.tech/Authentication_db/auth/.well-known/jwks.json";

            public String getJwksUri() {
                return jwksUri;
            }

            public void setJwksUri(String jwksUri) {
                this.jwksUri = jwksUri;
            }
        }
    }

    public static class Cors {
        private List<String> allowedOrigins = List.of(
                "http://localhost:3000",
                "http://localhost:5173",
                "http://localhost:8080"
        );
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");
        private List<String> allowedHeaders = List.of("*");
        private boolean allowCredentials = true;
        private long maxAge = 3600L;

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public List<String> getAllowedMethods() {
            return allowedMethods;
        }

        public void setAllowedMethods(List<String> allowedMethods) {
            this.allowedMethods = allowedMethods;
        }

        public List<String> getAllowedHeaders() {
            return allowedHeaders;
        }

        public void setAllowedHeaders(List<String> allowedHeaders) {
            this.allowedHeaders = allowedHeaders;
        }

        public boolean isAllowCredentials() {
            return allowCredentials;
        }

        public void setAllowCredentials(boolean allowCredentials) {
            this.allowCredentials = allowCredentials;
        }

        public long getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(long maxAge) {
            this.maxAge = maxAge;
        }
    }

    public static class RateLimiter {
        private boolean enabled = true;
        private int authRequestsPerMinute = 30;
        private int generalRequestsPerMinute = 180;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getAuthRequestsPerMinute() {
            return authRequestsPerMinute;
        }

        public void setAuthRequestsPerMinute(int authRequestsPerMinute) {
            this.authRequestsPerMinute = authRequestsPerMinute;
        }

        public int getGeneralRequestsPerMinute() {
            return generalRequestsPerMinute;
        }

        public void setGeneralRequestsPerMinute(int generalRequestsPerMinute) {
            this.generalRequestsPerMinute = generalRequestsPerMinute;
        }
    }
}
