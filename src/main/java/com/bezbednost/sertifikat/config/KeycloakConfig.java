package com.bezbednost.sertifikat.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {


    @Bean
    public Keycloak keycloak() {

        System.out.println("Initializing Keycloak Admin Client...");
        
        return KeycloakBuilder.builder()
                .serverUrl("http://localhost:8080")
                .realm("sertifikat")
                .clientId("my-backend") // The ID from Step 1
                .clientSecret("3PfADgyR1InW2pJr7HeOA5c0uAnbNkcd") // The Secret from Step 3
                .grantType("client_credentials") // This is the "Service Account" flow
                .build();
    }
}
