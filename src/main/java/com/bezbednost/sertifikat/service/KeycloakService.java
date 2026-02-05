package com.bezbednost.sertifikat.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import com.bezbednost.sertifikat.dto.RegisterRequest;
import com.bezbednost.sertifikat.entity.UserRole;

import jakarta.ws.rs.core.Response;

@Service
public class KeycloakService {
    private final Keycloak keycloak;
    private final String realm = "sertifikat";

    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    // ... tvoja metoda createUser ostaje ista ...
    public String createUser(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getEmail());
        user.setEmail(request.getEmail());
        user.setEnabled(false);
        user.setEmailVerified(false);

        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("firstName", List.of(request.getFirstName()));
        attributes.put("lastName", List.of(request.getLastName()));
        attributes.put("organisation", List.of(request.getOrganization()));
        attributes.put("role", List.of(UserRole.USER.name()));
        // Običan user ne mora da menja lozinku odmah
        attributes.put("mustChangePassword", List.of("false"));

        user.setAttributes(attributes);

        Response response = keycloak.realm(realm).users().create(user);

        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create user: " + response.getStatus());
        }

        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        setUserPassword(userId, request.getConfirmPassword(), false);
        return userId;
    }

    /**
     * IZMENA: CA User sada dobija temporary=false lozinku (da bi login prošao),
     * ali postavljamo atribut 'mustChangePassword' na 'true'.
     */
    public String createCAUser(String email, String firstName, String lastName, String organization, String temporaryPassword) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(email);
        user.setEmail(email);
        user.setEnabled(true);
        user.setEmailVerified(true);

        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("firstName", List.of(firstName));
        attributes.put("lastName", List.of(lastName));
        attributes.put("organisation", List.of(organization));
        attributes.put("role", List.of(UserRole.CA_USER.name()));

        // OVO JE KLJUČNO: Ručno postavljamo flag
        attributes.put("mustChangePassword", List.of("true"));

        user.setAttributes(attributes);

        Response response = keycloak.realm(realm).users().create(user);

        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create CA user: " + response.getStatus());
        }

        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

        // IZMENA: Šaljemo false umesto true. Keycloak neće tražiti promenu, ali naša aplikacija hoće (zbog atributa).
        setUserPassword(userId, temporaryPassword, false);

        return userId;
    }

    private void setUserPassword(String userId, String password, boolean isTemporary) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setTemporary(isTemporary);
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);

        keycloak.realm(realm).users().get(userId).resetPassword(credential);
    }

    // Metoda koju pozivaš kada korisnik promeni lozinku
    public void updatePassword(String email, String newPassword) {
        String userId = getUserIdByEmail(email);

        // 1. Promeni samu lozinku
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(newPassword);
        credential.setTemporary(false);

        keycloak.realm(realm).users().get(userId).resetPassword(credential);

        // 2. Ažuriraj atribut da više ne mora da menja
        updateUserAttribute(email, "mustChangePassword", "false");

        // (Opciono) Ukloni required actions ako su ostale greškom
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        if (user.getRequiredActions() != null && user.getRequiredActions().contains("UPDATE_PASSWORD")) {
            user.getRequiredActions().remove("UPDATE_PASSWORD");
            keycloak.realm(realm).users().get(userId).update(user);
        }
    }

    public void updateUserAttribute(String email, String attributeName, String value) {
        String userId = getUserIdByEmail(email);
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();

        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes == null) {
            attributes = new HashMap<>();
        }
        attributes.put(attributeName, List.of(value));
        user.setAttributes(attributes);

        keycloak.realm(realm).users().get(userId).update(user);
    }

    // ... ostatak klase (enableAndVerifyUser, getUserIdByEmail) ostaje isti ...
    public String getUserIdByEmail(String email) {
        List<UserRepresentation> users = keycloak.realm(realm).users().search(email);
        if (users.isEmpty()) throw new RuntimeException("User not found: " + email);
        return users.get(0).getId();
    }

    public void enableAndVerifyUser(String userId) {
        UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
        user.setEnabled(true);
        user.setEmailVerified(true);
        keycloak.realm(realm).users().get(userId).update(user);
    }
}