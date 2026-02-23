package com.bezbednost.sertifikat.config;

import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
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
    private final AuditLogger auditLogger;

    public SessionTrackingFilter(UserSessionService userSessionService, AuditLogger auditLogger) {
        this.userSessionService = userSessionService;
        this.auditLogger = auditLogger;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {

            String email     = jwt.getClaimAsString("email");
            String sessionId = jwt.getClaimAsString("sid");
            String ipAddress = getClientIp(request);
            String userAgent = request.getHeader("User-Agent");

            if (sessionId != null) {
                // Provera da li je sesija opozvana
                boolean isRevoked = userSessionService.isSessionRevoked(sessionId);

                if (isRevoked) {
                    // Logujemo pokušaj pristupa sa opozvаnom sesijom
                    auditLogger.logFailure(
                            AuditEventType.SESSION_BLOCKED_REVOKED,
                            email != null ? email : "UNKNOWN",
                            ipAddress,
                            "Blokiran pristup sa opozvаnom sesijom. SID=" + sessionId
                                    + " | URI=" + request.getRequestURI()
                    );

                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Session revoked\", \"message\": \"Sesija je opozvana.\"}");
                    return;
                }

                // Azuriranje aktivnosti sesije
                try {
                    if (email != null) {
                        userSessionService.trackUserSession(email, sessionId, ipAddress, userAgent, jwt);
                    }
                } catch (Exception e) {
                    // Ne prekidamo zahtev zbog greske u pracenju sesije,
                    // ali je logujemo kao sistemsku gresku
                    logger.error("Greska pri pracenju sesije: " + e.getMessage());
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}