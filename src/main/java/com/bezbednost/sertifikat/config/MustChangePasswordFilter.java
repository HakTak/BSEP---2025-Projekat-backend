package com.bezbednost.sertifikat.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class MustChangePasswordFilter extends OncePerRequestFilter {

    private static final String CHANGE_PASSWORD_ENDPOINT = "/api/auth/change-password";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {

            String role = jwt.getClaimAsString("role");
            String mustChange = jwt.getClaimAsString("mustChangePassword");

            boolean mustChangePassword = "true".equalsIgnoreCase(mustChange);
            String path = request.getRequestURI();

            if ("CA_USER".equals(role) && mustChangePassword) {

                // DOZVOLJENO SAMO menjanje lozinke
                if (!path.equals(CHANGE_PASSWORD_ENDPOINT)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("""
                        {
                          "error": "PASSWORD_CHANGE_REQUIRED",
                          "message": "Morate promeniti lozinku pre nastavka."
                        }
                        """);
                    return;
                }
            }
            else{
                if (path.equals(CHANGE_PASSWORD_ENDPOINT)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("""
                        {
                          "error": "PASSWORD_CHANGE_FORBIDDEN",
                          "message": "Lozinku mozete menjati ovom funkcijom samo jednom"
                        }
                        """);
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
