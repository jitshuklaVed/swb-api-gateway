package com.smapp.gateway.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, Mono<? extends AbstractAuthenticationToken>> {

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        String principalName = jwt.getSubject() != null ? jwt.getSubject() : jwt.getClaimAsString("username");
        if (principalName == null) {
            principalName = "unknown";
        }
        return Mono.just(new JwtAuthenticationToken(jwt, authorities, principalName));
    }

    public Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // 1. Check "roles" claim (List or String)
        Object rolesObj = jwt.getClaims().get("roles");
        if (rolesObj instanceof Collection<?> roles) {
            for (Object role : roles) {
                if (role != null) {
                    addAuthority(authorities, role.toString());
                }
            }
        } else if (rolesObj instanceof String roleStr) {
            addAuthority(authorities, roleStr);
        }

        // 2. Check "authorities" claim
        Object authObj = jwt.getClaims().get("authorities");
        if (authObj instanceof Collection<?> auths) {
            for (Object auth : auths) {
                if (auth != null) {
                    addAuthority(authorities, auth.toString());
                }
            }
        }

        // 3. Check "role" claim
        String singleRole = jwt.getClaimAsString("role");
        if (singleRole != null) {
            addAuthority(authorities, singleRole);
        }

        // 4. Check "scope" or "scp"
        Object scpObj = jwt.getClaims().get("scope");
        if (scpObj == null) {
            scpObj = jwt.getClaims().get("scp");
        }
        if (scpObj instanceof String scpStr) {
            for (String scope : scpStr.split(" ")) {
                if (!scope.isBlank()) {
                    addAuthority(authorities, scope);
                }
            }
        } else if (scpObj instanceof Collection<?> scopes) {
            for (Object scope : scopes) {
                if (scope != null) {
                    addAuthority(authorities, scope.toString());
                }
            }
        }

        return authorities;
    }

    private void addAuthority(List<GrantedAuthority> authorities, String roleName) {
        String clean = roleName.trim();
        if (clean.isEmpty()) {
            return;
        }

        if (clean.startsWith("ROLE_")) {
            authorities.add(new SimpleGrantedAuthority(clean));
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + clean.toUpperCase()));
            authorities.add(new SimpleGrantedAuthority(clean));
        }
    }
}
