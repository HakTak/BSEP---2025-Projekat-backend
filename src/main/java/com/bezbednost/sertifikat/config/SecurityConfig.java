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

    private final SessionTrackingFilter sessionTrackingFilter;
    private final MustChangePasswordFilter mustChangePasswordFilter;
    private final RequestLoggingFilter requestLoggingFilter;

    public SecurityConfig(
            SessionTrackingFilter sessionTrackingFilter,
            MustChangePasswordFilter mustChangePasswordFilter,
            RequestLoggingFilter requestLoggingFilter
    ) {
        this.sessionTrackingFilter = sessionTrackingFilter;
        this.mustChangePasswordFilter = mustChangePasswordFilter;
        this.requestLoggingFilter = requestLoggingFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/activate",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/api/certificates/download",
                                "/api/certificates/check"
                        ).permitAll()
                        .anyRequest().authenticated()
                )

                .oauth2ResourceServer(oauth2 -> oauth2.jwt(
                        jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtRolesConverter())))

                // 1. RequestLoggingFilter – na vrhu, prvi se izvrsava, pre SessionTrackingFilter-a
                .addFilterAfter(requestLoggingFilter, BasicAuthenticationFilter.class)
                // 2. SessionTrackingFilter – posle RequestLoggingFilter-a
                .addFilterAfter(sessionTrackingFilter, RequestLoggingFilter.class)
                // 3. MustChangePasswordFilter – poslednji u nizu
                .addFilterAfter(mustChangePasswordFilter, SessionTrackingFilter.class)

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