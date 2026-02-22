package com.bezbednost.sertifikat.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // --- IZMENA 1: Injektujemo naš custom filter za sesije ---
    private final SessionTrackingFilter sessionTrackingFilter;
    private final MustChangePasswordFilter mustChangePasswordFilter;

    public SecurityConfig(
            SessionTrackingFilter sessionTrackingFilter,
            MustChangePasswordFilter mustChangePasswordFilter
    ) {
        this.sessionTrackingFilter = sessionTrackingFilter;
        this.mustChangePasswordFilter = mustChangePasswordFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1. CORS KONFIGURACIJA
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 2. CSRF
                .csrf(AbstractHttpConfigurer::disable)

                // 3. SESSION MANAGEMENT (Stateless)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        // Ovi endpointi moraju biti javni (bez tokena)
                        .requestMatchers(
                                "/api/auth/login",            // <--- OVO TI JE FALILO!
                                "/api/auth/register",
                                "/api/auth/activate",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                "/swagger-ui.html",
                                "/api/certificates/check",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/api/certificates/download"
                        ).permitAll()
                        .anyRequest().authenticated()
                )

                // Konfiguracija za Keycloak (OAuth2 Resource Server)
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(
                        jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtRolesConverter())))

                // --- IZMENA 2: Dodajemo naš filter u lanac ---
                // Dodajemo ga NAKON BasicAuthenticationFilter-a.
                // U ovom trenutku Spring je već proverio JWT token i popunio SecurityContext,
                // tako da naš filter može da pročita podatke o korisniku.
                .addFilterAfter(sessionTrackingFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(mustChangePasswordFilter, SessionTrackingFilter.class)

                // 5. ISKLJUČIVANJE DEFAULT LOGIN FORMI
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Tvoj React frontend
        configuration.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "https://localhost:5173",
                "http://localhost:5174",
                "https://localhost:5174"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}