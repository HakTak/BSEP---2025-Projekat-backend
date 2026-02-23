package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.*;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
import com.bezbednost.sertifikat.service.CertificateService;
import com.bezbednost.sertifikat.service.KeycloakService;
import com.bezbednost.sertifikat.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"https://localhost:5173", "https://localhost:5174"})
public class AuthController {

    @Autowired private UserService userService;
    @Autowired private KeycloakService keycloakService;
    @Autowired private CertificateService certificateService;
    @Autowired private AuditLogger auditLogger;

    // ----------------------------------------------------------------
    // Registracija
    // ----------------------------------------------------------------
    @PostMapping("/register")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        try {
            RegisterResponse response = userService.register(request);
            keycloakService.createUser(request);
            auditLogger.logSuccess(AuditEventType.USER_REGISTER, request.getEmail(), ip,
                    "Registracija uspesna za korisnika: " + request.getEmail());
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.USER_REGISTER, request.getEmail(), ip,
                    "Registracija neuspesna: " + e.getMessage());
            throw e;
        }
    }

    // ----------------------------------------------------------------
    // Kreiranje CA korisnika (admin)
    // ----------------------------------------------------------------
    @PostMapping("/register-ca")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> registerCA(
            @Valid @RequestBody RegisterCaCompositeRequest request,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        String adminEmail = getCurrentUserEmail(httpRequest);
        try {
            userService.registerCAUser(request.getUserRequest());
            User newCaUser = userService.getUserByEmail(request.getUserRequest().getEmail());

            com.bezbednost.sertifikat.model.Certificate cert = certificateService.createCACertKeystore(
                    request.getCertificateRequest(), newCaUser);

            auditLogger.logSuccess(AuditEventType.ADMIN_CREATE_CA_USER, adminEmail, ip,
                    "Admin kreirao CA korisnika: " + request.getUserRequest().getEmail());
            auditLogger.logSuccess(AuditEventType.ADMIN_CREATE_CA_CERT, adminEmail, ip,
                    "Kreiran CA sertifikat sa SN=" + cert.getSerialNumber()
                            + " za korisnika: " + newCaUser.getEmail());

            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.ADMIN_CREATE_CA_USER, adminEmail, ip,
                    "Neuspesno kreiranje CA korisnika " + request.getUserRequest().getEmail()
                            + ": " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Promena lozinke (CA korisnik pri prvom loginu)
    // ----------------------------------------------------------------
    @PostMapping("/change-password")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        String userEmail = getCurrentUserEmail(httpRequest);
        try {
            userService.changeCaUserPassword(request);
            auditLogger.logSuccess(AuditEventType.USER_CHANGE_PASSWORD, userEmail, ip,
                    "CA korisnik uspesno promenio lozinku");
            return ResponseEntity.ok(Map.of("message", "Lozinka uspešno promenjena"));
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.USER_CHANGE_PASSWORD, userEmail, ip,
                    "Promena lozinke neuspesna: " + e.getMessage());
            throw e;
        }
    }

    // ----------------------------------------------------------------
    // Aktivacija naloga
    // ----------------------------------------------------------------
    @PostMapping("/activate")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<Map<String, String>> activate(
            @RequestParam String token,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        try {
            User user = userService.activateAccount(token);
            keycloakService.enableAndVerifyUser(keycloakService.getUserIdByEmail(user.getEmail()));
            auditLogger.logSuccess(AuditEventType.USER_ACTIVATE_ACCOUNT, user.getEmail(), ip,
                    "Nalog uspesno aktiviran za: " + user.getEmail());
            Map<String, String> response = new HashMap<>();
            response.put("message", "Nalog je uspešno aktiviran! Sada možete da se ulogujete.");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            auditLogger.logFailure(AuditEventType.USER_ACTIVATE_ACCOUNT_FAIL, "UNKNOWN", ip,
                    "Neuspesna aktivacija naloga: " + e.getMessage());
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Zaboravljena lozinka
    // ----------------------------------------------------------------
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        try {
            userService.forgotPassword(request);
            // Logujemo samo da je zahtev primljen, ne da li postoji nalog
            // (security through obscurity – ne otkrivamo da li email postoji)
            auditLogger.logSuccess(AuditEventType.USER_FORGOT_PASSWORD, request.getEmail(), ip,
                    "Zahtev za reset lozinke primljen za: " + request.getEmail());
            Map<String, String> response = new HashMap<>();
            response.put("message", "Email za oporavak lozinke je poslat na vašu email adresu.");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.USER_FORGOT_PASSWORD, request.getEmail(), ip,
                    "Neuspesno slanje reset emaila: " + e.getMessage());
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Reset lozinke
    // ----------------------------------------------------------------
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {

        String ip = getClientIp(httpRequest);
        try {
            userService.resetPassword(request);
            // Ne logujemo token u poruci – to je osetljiv podatak
            auditLogger.logSuccess(AuditEventType.USER_RESET_PASSWORD, "VIA_TOKEN", ip,
                    "Lozinka uspesno resetovana putem tokena");
            Map<String, String> response = new HashMap<>();
            response.put("message", "Lozinka je uspešno resetovana!");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.USER_RESET_PASSWORD, "VIA_TOKEN", ip,
                    "Reset lozinke neuspesan: " + e.getMessage());
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Provera jacine lozinke (nije audit dogadjaj – ne loguje se)
    // ----------------------------------------------------------------
    @PostMapping("/checkPasswordStrength")
    public ResponseEntity<PasswordStrengthResponse> checkPasswordStrength(
            @RequestBody Map<String, String> request) {
        String password = request.get("password");
        if (password == null || password.isEmpty()) {
            return new ResponseEntity<>(
                    PasswordStrengthResponse.builder()
                            .valid(false)
                            .errors(List.of("Lozinka ne sme biti prazna"))
                            .build(),
                    HttpStatus.BAD_REQUEST
            );
        }
        return new ResponseEntity<>(userService.checkPasswordStrength(password), HttpStatus.OK);
    }

//    // ----------------------------------------------------------------
//    // CRUD operacije na korisnicima
//    // ----------------------------------------------------------------
//    @GetMapping("/{id}")
//    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
//        return new ResponseEntity<>(userService.getUserById(id), HttpStatus.OK);
//    }
//
//    @GetMapping("/email/{email}")
//    public ResponseEntity<UserResponse> getUserByEmail(@PathVariable String email) {
//        return new ResponseEntity<>(userService.getUserDtoByEmail(email), HttpStatus.OK);
//    }
//
//    @GetMapping("/allUsers")
//    public ResponseEntity<List<UserResponse>> getAllUsers() {
//        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
//    }
//
//    @PutMapping("update/{id}")
//    public ResponseEntity<UserResponse> updateUser(
//            @PathVariable Long id,
//            @Valid @RequestBody UpdateUserRequest request,
//            HttpServletRequest httpRequest) {
//
//        String ip = getClientIp(httpRequest);
//        String actorEmail = getCurrentUserEmail(httpRequest);
//        UserResponse response = userService.updateUser(id, request);
//        auditLogger.logSuccess(AuditEventType.USER_UPDATE_PROFILE, actorEmail, ip,
//                "Profil korisnika azuriran. Ciljni ID=" + id);
//        return new ResponseEntity<>(response, HttpStatus.OK);
//    }
//
//    @DeleteMapping("/{id}")
//    public ResponseEntity<Void> deleteUser(
//            @PathVariable Long id,
//            HttpServletRequest httpRequest) {
//
//        String ip = getClientIp(httpRequest);
//        String actorEmail = getCurrentUserEmail(httpRequest);
//        userService.deleteUser(id);
//        auditLogger.logSuccess(AuditEventType.USER_DELETE, actorEmail, ip,
//                "Korisnik obrisan. ID=" + id);
//        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
//    }

    // ----------------------------------------------------------------
    // Pomocne metode
    // ----------------------------------------------------------------

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }

    /**
     * Pokusava da izvuce email autentifikovanog korisnika iz SecurityContext-a.
     * Vraca "ANONYMOUS" ako korisnik nije autentifikovan (javni endpointi).
     */
    private String getCurrentUserEmail(HttpServletRequest request) {
        try {
            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder
                            .getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
                String email = jwt.getClaimAsString("email");
                if (email == null) email = jwt.getClaimAsString("preferred_username");
                return email != null ? email : "UNKNOWN";
            }
        } catch (Exception ignored) { }
        return "ANONYMOUS";
    }
}