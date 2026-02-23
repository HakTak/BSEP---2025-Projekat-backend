package com.bezbednost.sertifikat.config;

import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;

/**
 * Filter koji automatski loguje svaki HTTP zahtev.
 *
 * Loguje se:
 *  - HTTP metoda i URI
 *  - IP adresa klijenta
 *  - Autentifikovani korisnik (email iz JWT tokena, ako postoji)
 *  - HTTP status koda odgovora
 *  - Vreme izvrsavanja zahteva (ms)
 *
 * Za 4xx i 5xx odgovore loguje se i kao audit FAILURE dogadjaj.
 *
 * @Order(1) osigurava da se ovaj filter izvrsava pre ostalih custom filtera.
 */
@Component
@Order(1)
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger appLog = LoggerFactory.getLogger(RequestLoggingFilter.class);
    private final AuditLogger auditLogger;

    // Putanje koje ne logujemo (smanjuje buku za healthcheck/swagger)
    private static final String[] SKIP_PATHS = {
            "/swagger-ui",
            "/v3/api-docs",
            "/actuator/health"
    };

    public RequestLoggingFilter(AuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Preskoci logovanje za swagger i slicne pomocne putanje
        if (shouldSkip(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Umotavamo response da bismo mogli da ocitamo status kod NAKON sto se zahtev obradi
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        long startTime = System.currentTimeMillis();
        String ipAddress = getClientIp(request);
        String method    = request.getMethod();
        String uri       = request.getRequestURI();

        try {
            filterChain.doFilter(request, wrappedResponse);
        } finally {
            long duration   = System.currentTimeMillis() - startTime;
            int  statusCode = wrappedResponse.getStatus();

            // Ocitavamo korisnika iz SecurityContext-a (vec je popunjen od strane Spring Security)
            String userId = extractUserId();

            // Generalni app log – svaki zahtev
            appLog.info("{} {} | status={} | ip={} | user={} | {}ms",
                    method, uri, statusCode, ipAddress, userId, duration);

            // Audit log samo za bezbednosno relevantne situacije
            if (statusCode == 401) {
                auditLogger.logFailure(
                        AuditEventType.UNAUTHORIZED_REQUEST,
                        userId, ipAddress,
                        "Neautorizovani pristup: " + method + " " + uri
                );
            } else if (statusCode == 403) {
                auditLogger.logFailure(
                        AuditEventType.ACCESS_DENIED,
                        userId, ipAddress,
                        "Zabranjen pristup: " + method + " " + uri
                );
            } else if (statusCode >= 500) {
                auditLogger.logFailure(
                        AuditEventType.SYSTEM_ERROR,
                        userId, ipAddress,
                        "Serverska greska: " + method + " " + uri + " | status=" + statusCode
                );
            }

            // Obavezno kopiraj response body nazad klijentu
            wrappedResponse.copyBodyToResponse();
        }
    }

    // ----------------------------------------------------------------
    // Pomocne metode
    // ----------------------------------------------------------------

    /**
     * Pokusava da izvuce email iz JWT tokena u SecurityContext-u.
     * Vraca "ANONYMOUS" ako korisnik nije autentifikovan.
     */
    private String extractUserId() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
                String email = jwt.getClaimAsString("email");
                if (email == null) email = jwt.getClaimAsString("preferred_username");
                return email != null ? email : "UNKNOWN";
            }
        } catch (Exception ignored) {
            // Nije kriticno – samo ne mozemo da ocitamo korisnika
        }
        return "ANONYMOUS";
    }

    /**
     * Podrzava X-Forwarded-For header (za aplikacije iza proxy/load balancera).
     */
    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean shouldSkip(String uri) {
        for (String skip : SKIP_PATHS) {
            if (uri.startsWith(skip)) return true;
        }
        return false;
    }
}