package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.service.KeycloakSessionService;
import com.bezbednost.sertifikat.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;
    public UserController(UserService userService) {
        this.userService = userService;
    }

//    @GetMapping("/my-profile")
//    @PreAuthorize("isAuthenticated()")
//    public Map<String, Object> getMyProfile(Authentication authentication) {
//        // Objekat 'authentication' sadrži informacije o ulogovanom korisniku
//        // Spring Security automatski popunjava ovaj objekat na osnovu JWT-a
//
//        userService.getUserById();
//
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
//            Jwt jwt = (Jwt) authentication.getPrincipal();
//            Map<String, Object> claims = jwt.getClaims();
//
//            // Svi claims iz JWT-a su sada dostupni u mapi
//            // Možeš im pristupiti direktno
//            // String userId = jwt.getSubject(); // Standardni ID korisnika
//            // String username = jwt.getClaimAsString("preferred_username");
//            // String email = jwt.getClaimAsString("email");
//            // String sessionId = jwt.getClaimAsString("sid"); // Keycloak-ov Session ID
//            // String customSessionId = jwt.getClaimAsString("userSessionID"); // Ako si ga tako mapirao
//
//            // Vratićemo sve claims za demonstraciju
//            return claims;
//        }
//        return Map.of("message", "Korisnik nije autentifikovan ili je token neispravan.");
//    }

//    @GetMapping("/active-sessions")
//    @PreAuthorize("isAuthenticated()")
//    public ResponseEntity<List<Map<String, String>>> getActiveSessions(Authentication authentication) {
//        List<Map<String, String>> sessions = keycloakSessionService.getUserActiveSessions(authentication);
//        return ResponseEntity.ok(sessions);
//    }

//    @PostMapping("/revoke-session/{sessionId}")
//    @PreAuthorize("isAuthenticated()")
//    public ResponseEntity<String> revokeSession(@PathVariable String sessionId, Authentication authentication) {
//        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
//            return ResponseEntity.status(401).body("Not authenticated.");
//        }
//        Jwt jwt = (Jwt) authentication.getPrincipal();
//        String userId = jwt.getSubject(); // Keycloak-ov interni user ID
//
//        try {
//            // keycloakSessionService.revokeUserSession(authentication, sessionId); // Ako hoćeš sve da izbaciš
//            keycloakSessionService.revokeSingleUserSession(userId, sessionId); // Opoziv samo jedne sesije
//            return ResponseEntity.ok("Session " + sessionId + " successfully revoked.");
//        } catch (IllegalArgumentException e) {
//            return ResponseEntity.badRequest().body(e.getMessage());
//        } catch (Exception e) {
//            return ResponseEntity.status(500).body("Error revoking session: " + e.getMessage());
//        }
//    }
}
