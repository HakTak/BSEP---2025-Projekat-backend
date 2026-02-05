package com.bezbednost.sertifikat.config;

import com.bezbednost.sertifikat.entity.UserRole;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeycloakJwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // Defaultni konverter koji preuzima Scopes (npr. "SCOPE_openid")
    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Spajamo standardne scope-ove i naše role
        Collection<GrantedAuthority> authorities = Stream.concat(
                defaultGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractRealmRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<? extends GrantedAuthority> extractRealmRoles(Jwt jwt) {
        // Keycloak stavlja realm role u "realm_access" claim
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

        if (realmAccess == null || !realmAccess.containsKey("roles")) {
            return Collections.emptySet();
        }

        @SuppressWarnings("unchecked")
        Collection<String> rawRoles = (Collection<String>) realmAccess.get("roles");

        // Pretvaramo sve role iz Keycloaka u velika slova da ne bi bilo problema (admin vs ADMIN)
        Set<String> roles = rawRoles.stream()
                .map(String::toUpperCase)
                .collect(Collectors.toSet());

        // --- LOGIKA PRIORITETA (HIJERARHIJA) ---

        // 1. Ako ima ADMIN rolu, on je ADMIN (najviši prioritet)
        if (roles.contains(UserRole.ADMIN.name())) {
            return Set.of(new SimpleGrantedAuthority("ROLE_" + UserRole.ADMIN.name()));
        }

        // 2. Ako nije Admin, proveravamo da li je CA_USER
        if (roles.contains(UserRole.CA_USER.name())) {
            return Set.of(new SimpleGrantedAuthority("ROLE_" + UserRole.CA_USER.name()));
        }

        // 3. Ako nije ni to, proveravamo da li je običan USER
        if (roles.contains(UserRole.USER.name())) {
            return Set.of(new SimpleGrantedAuthority("ROLE_" + UserRole.USER.name()));
        }

        // Ako nema prepoznatu rolu
        return Collections.emptySet();
    }
}