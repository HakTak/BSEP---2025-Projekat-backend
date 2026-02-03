package com.bezbednost.sertifikat.service;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.UserSessionRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class KeycloakSessionService {

    private final Keycloak keycloak;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri; // Treba nam URL Keycloak-a da izvučemo Realm ime

    public KeycloakSessionService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    private String getRealmName() {
        // Issuer URI je obično http://localhost:8080/realms/sertifikat
        // Izvlačimo "sertifikat"
        return issuerUri.substring(issuerUri.lastIndexOf('/') + 1);
    }

    public List<Map<String, String>> getUserActiveSessions(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
            throw new IllegalArgumentException("Authentication required.");
        }

        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getSubject(); // Ovo je Keycloak-ov interni user ID

        UsersResource usersResource = keycloak.realm(getRealmName()).users();
        UserResource userResource = usersResource.get(userId);

        List<UserSessionRepresentation> sessions = userResource.getUserSessions();

        return sessions.stream().map(session -> Map.of(
                "sessionId", session.getId(),
                "ipAddress", session.getIpAddress(),
                "start", String.valueOf(session.getStart()),
                "lastAccess", String.valueOf(session.getLastAccess()),
                "client", session.getUserId() // Koji klijent je koristio sesiju
        )).collect(Collectors.toList());
    }

    public void revokeUserSession(Authentication authentication, String sessionIdToRevoke) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
            throw new IllegalArgumentException("Authentication required.");
        }

        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getSubject(); // Keycloak-ov interni user ID

        UsersResource usersResource = keycloak.realm(getRealmName()).users();
        UserResource userResource = usersResource.get(userId);

        // Prekid sesije na Keycloak-u
        // Ova metoda Keycloak admin clienta izloguje korisnika iz SVIH sesija
        // Postoji i granularnija metoda za specifičnu sesiju ako ti zatreba (session.logout())
        // Ali za jednostavnost, ovo izbacuje iz svih.
        // Ako hoćeš samo jednu sesiju da ugasiš, moraš da pretražiš sessions listu
        // userResource.getUserSessions().stream().filter(s -> s.getId().equals(sessionIdToRevoke)).findFirst().ifPresent(s -> s.logout());

        // Zahteva manage-users rolu
        userResource.logout(); // Izloguje korisnika iz svih sesija
        // Opciono: obrisati lokalni token sa frontenda za trenutnu sesiju
    }

    // Metoda za opoziv SAMO jedne sesije, na osnovu Session ID-a
    public void revokeSingleUserSession(String userId, String sessionIdToRevoke) {
        UsersResource usersResource = keycloak.realm(getRealmName()).users();
        UserResource userResource = usersResource.get(userId);

        List<UserSessionRepresentation> sessions = userResource.getUserSessions();
        for (UserSessionRepresentation session : sessions) {
            if (session.getId().equals(sessionIdToRevoke)) {
                // Zahteva da Service Account ima 'manage-users' rolu
                keycloak.realm(getRealmName()).deleteSession(session.getId(), false);
                return;
            }
        }
        throw new IllegalArgumentException("Session not found for user.");
    }

}