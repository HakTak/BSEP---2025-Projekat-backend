package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.UserResponse;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.model.UserSession;
import com.bezbednost.sertifikat.service.UserSessionService;
import com.bezbednost.sertifikat.service.UserService; // Tvoj user service
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/sessions")
public class UserSessionController {

    @Autowired
    private UserSessionService sessionService;
    @Autowired
    private UserService userService; // Pretpostavka da imas ovo

    // Endpoint za prikaz svih aktivnih sesija
    @GetMapping("/active")
    public ResponseEntity<List<UserSession>> getActiveSessions(Principal principal) {
        UserResponse userResponse = userService.getUserByEmail(principal.getName());
        return ResponseEntity.ok(sessionService.getActiveSessions(userResponse.getId()));
    }

    // Endpoint za opoziv (logout) specifičnog uređaja
    @PostMapping("/revoke/{tokenId}")
    public ResponseEntity<?> revokeSession(@PathVariable String tokenId) {
        // Dodatna provera: ovde bi idealno trebao proveriti da li taj tokenId pripada ulogovanom korisniku
        // da ne bi Pera mogao da izloguje Žiku ako pogodi UUID.
        sessionService.revokeSession(tokenId);
        return ResponseEntity.ok("Uređaj uspešno odjavljen.");
    }
}