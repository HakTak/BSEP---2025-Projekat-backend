package com.bezbednost.sertifikat.config;

import com.bezbednost.sertifikat.service.UserSessionService;
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
public class SessionTrackingFilter extends OncePerRequestFilter {

    private final UserSessionService userSessionService;

    public SessionTrackingFilter(UserSessionService userSessionService) {
        this.userSessionService = userSessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            String email = jwt.getClaimAsString("email");
            String sessionId = jwt.getClaimAsString("sid"); // Keycloak Session ID
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");

            if (sessionId != null) {
                // 1. BLOKIRANJE: Proveri u bazi da li je sesija opozvana
                boolean isRevoked = userSessionService.isSessionRevoked(sessionId);

                if (isRevoked) {
                    // Opozvana je! Brišemo auth kontekst
                    SecurityContextHolder.clearContext();

                    // Vraćamo 401 Unauthorized da frontend zna da treba da uradi logout
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Session revoked\", \"message\": \"Sesija je opozvana.\"}");

                    // Prekidamo lanac - zahtev NE ide dalje ka kontroleru
                    return;
                }

                // 2. Ažuriranje vremena aktivnosti (ako nije blokirana)
                try {
                    if (email != null) {
                        userSessionService.trackUserSession(email, sessionId, ipAddress, userAgent, jwt);
                    }
                } catch (Exception e) {
                    System.err.println("Greska pri pracenju sesije: " + e.getMessage());
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}