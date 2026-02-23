package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.UserSessionDTO;
import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
import com.bezbednost.sertifikat.service.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
public class UserSessionController {

    private final UserSessionService userSessionService;
    private final AuditLogger auditLogger;

    public UserSessionController(UserSessionService userSessionService, AuditLogger auditLogger) {
        this.userSessionService = userSessionService;
        this.auditLogger = auditLogger;
    }

    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<UserSessionDTO>> getActiveSessions(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest request) {

        String email     = jwt.getClaimAsString("email");
        String sessionId = jwt.getClaimAsString("sid");
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        userSessionService.trackUserSession(email, sessionId, ipAddress, userAgent, jwt);

        return ResponseEntity.ok(userSessionService.getUserSessions(email));
    }

    @PostMapping("/sessions/revoke/{sessionId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> revokeSession(
            @PathVariable String sessionId,
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest request) {

        String email = jwt.getClaimAsString("email");
        String ip    = getClientIp(request);

        userSessionService.revokeSession(sessionId);
        auditLogger.logSuccess(AuditEventType.SESSION_REVOKED, email, ip,
                "Korisnik opozao sesiju. SID=" + sessionId);

        return ResponseEntity.ok("Sesija uspešno opozvana i zabeležena u bazi.");
    }

    @PutMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> logout(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest request) {

        String email     = jwt.getClaimAsString("email");
        String sessionId = jwt.getClaimAsString("sid");
        String ip        = getClientIp(request);

        userSessionService.revokeActiveSession();
        auditLogger.logSuccess(AuditEventType.USER_LOGOUT, email, ip,
                "Korisnik se odjavio. SID=" + sessionId);

        return ResponseEntity.ok("Sesija uspešno opozvana i zabeležena u bazi.");
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}