package com.bezbednost.sertifikat.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {
	@Bean
    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl("http://localhost:8080")
                .realm("master") // ili realm gde je admin client
                .clientId("my-backend")
                .clientSecret("YOUR_SECRET")
                .grantType("client_credentials")
                .build();
    }
}