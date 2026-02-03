package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.UserSessionDTO;
import com.bezbednost.sertifikat.service.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
public class UserSessionController {

    private final UserSessionService userSessionService;

    public UserSessionController(UserSessionService userSessionService) {
        this.userSessionService = userSessionService;
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<UserSessionDTO>> getActiveSessions(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        // Izvlačimo podatke iz JWT tokena
        String email = jwt.getClaimAsString("email"); // ili "preferred_username" zavisno od Keycloaka
        String sessionId = jwt.getClaimAsString("sid"); // Keycloak Session ID

        // Opciono: Ažuriraj trenutnu sesiju u bazi da znamo da je korisnik živ
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        userSessionService.trackUserSession(email, sessionId, ipAddress, userAgent, jwt);

        // Vrati sve sesije
        return ResponseEntity.ok(userSessionService.getUserSessions(email));
    }

    @PostMapping("/sessions/revoke/{sessionId}")
    public ResponseEntity<String> revokeSession(@PathVariable String sessionId) {
        userSessionService.revokeSession(sessionId);
        return ResponseEntity.ok("Sesija uspešno opozvana i zabeležena u bazi.");
    }
}