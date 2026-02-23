package com.bezbednost.sertifikat.config;

import com.bezbednost.sertifikat.entity.UserRole;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public class KeycloakJwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // 1. Čitamo claim "role" koji smo definisali u Keycloak maperu
        String roleClaim = jwt.getClaimAsString("role");
        // Ako nema role u tokenu, vraćamo praznu listu prava
        if (roleClaim == null || roleClaim.isEmpty()) {
            return new JwtAuthenticationToken(jwt, Collections.emptySet());
        }

        // 2. Konvertujemo string u UserRole Enum da budemo sigurni da je validan
        // Koristimo try-catch u slučaju da u Keycloaku piše nešto glupo (npr. "HAKER")
        UserRole userRole;
        try {
            userRole = UserRole.valueOf(roleClaim.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Ako rola nije prepoznata (nije ADMIN, USER ili CA_USER), ignorišemo je
            return new JwtAuthenticationToken(jwt, Collections.emptySet());
        }

        // 3. Pravimo Spring Authority. OBAVEZNO mora imati prefiks "ROLE_"
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + userRole.name());

        return new JwtAuthenticationToken(jwt, Set.of(authority));
    }
}