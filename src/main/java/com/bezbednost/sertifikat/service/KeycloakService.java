package com.bezbednost.sertifikat.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import com.bezbednost.sertifikat.dto.RegisterRequest;

import jakarta.ws.rs.core.Response;

@Service
public class KeycloakService {
	private final Keycloak keycloak;
    private final String realm = "sertifikat";

    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    /** Create a new user, initially disabled */
    public String createUser(RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.getEmail());           // Email as username
        user.setEmail(request.getEmail());
        user.setEnabled(false);            // Initially disabled
        user.setEmailVerified(false);
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("firstName", List.of(request.getFirstName()));
        attributes.put("lastName", List.of(request.getLastName()));
        attributes.put("organisation", List.of(request.getOrganization()));
        user.setAttributes(attributes);

        Response response = keycloak.realm(realm)
                .users()
                .create(user);

        if (response.getStatus() != 201) {
            throw new RuntimeException("Failed to create user: " + response.getStatus());
        }

        // Get the created user's ID from the Location header
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

        // Set initial password
        setUserPassword(userId, request.getConfirmPassword());

        return userId;
    }

    /** Set or update user password */
    private void setUserPassword(String userId, String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setTemporary(false); // User doesn't have to change at first login
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);

        keycloak.realm(realm)
                .users()
                .get(userId)
                .resetPassword(credential);
    }

    /** Enable user and mark email verified */
    public void enableAndVerifyUser(String userId) {
        UserRepresentation user = keycloak.realm(realm)
                .users()
                .get(userId)
                .toRepresentation();

        user.setEnabled(true);
        user.setEmailVerified(true);

        keycloak.realm(realm)
                .users()
                .get(userId)
                .update(user);
    }

    /** Find user ID by email */
    public String getUserIdByEmail(String email) {
        List<UserRepresentation> users = keycloak.realm(realm)
                .users()
                .search(email);

        if (users.isEmpty()) {
            throw new RuntimeException("User not found: " + email);
        }

        return users.get(0).getId();
    }
}
