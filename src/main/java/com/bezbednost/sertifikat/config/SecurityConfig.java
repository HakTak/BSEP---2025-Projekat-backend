package com.bezbednost.sertifikat.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1. CORS KONFIGURACIJA
                // Povezujemo CORS konfiguraciju definisanu u corsConfigurationSource() metodi ispod
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 2. CSRF
                // Isključujemo CSRF jer koristimo Stateless sesiju (JWT ili slično) i React
                .csrf(AbstractHttpConfigurer::disable)

                // 3. SESSION MANAGEMENT
                // Postavljamo sesiju na STATELESS (kao u vežbama), jer REST API ne treba da pamti stanje sesije na serveru
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 4. AUTORIZACIJA PUTANJA (Zamena za configure(HttpSecurity) i configure(WebSecurity))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/register", "/api/auth/activate", "/api/auth/forgot-password", "/api/auth/reset-password", "/swagger-ui.html", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        .anyRequest().permitAll()
                )

                // 5. ISKLJUČIVANJE DEFAULT LOGIN FORMI
                // Isključujemo default login formu i basic auth jer će React slati podatke (JSON)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Definicija CORS-a (Zamena za CorsConfig klasu iz vežbi)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Dozvoljavamo tvoj React frontend (Vite port)
        // NAPOMENA: Ako ti React radi na HTTP (ne HTTPS), promeni u "http://localhost:5173"
        configuration.setAllowedOrigins(List.of("http://localhost:5173", "https://localhost:5173"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true); // Ako šalješ kolačiće ili Auth header
        configuration.setMaxAge(3600L); // Iz vežbi (preflight cache)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}