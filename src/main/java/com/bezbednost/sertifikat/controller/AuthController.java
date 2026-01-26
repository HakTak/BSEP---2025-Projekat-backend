package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.PasswordStrengthResponse;
import com.bezbednost.sertifikat.dto.RegisterRequest;
import com.bezbednost.sertifikat.dto.RegisterResponse;
import com.bezbednost.sertifikat.dto.UpdateUserRequest;
import com.bezbednost.sertifikat.dto.UserResponse;
import com.bezbednost.sertifikat.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173")
public class AuthController {
    
    @Autowired
    private UserService userService;
    
    // CREATE - Registracija
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = userService.register(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
    
    // ACTIVATE - Aktivacija naloga
    @PostMapping("/activate")
    public ResponseEntity<Map<String, String>> activate(@RequestParam String token) {
        try {
            userService.activateAccount(token);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Nalog je uspešno aktiviran! Sada možete da se ulogujete.");
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }
    
    // CHECK PASSWORD STRENGTH
    @PostMapping("/checkPasswordStrength")
    public ResponseEntity<PasswordStrengthResponse> checkPasswordStrength(@RequestBody Map<String, String> request) {
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
        PasswordStrengthResponse response = userService.checkPasswordStrength(password);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    
    // READ - Pronađi korisnika po ID-u
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        UserResponse response = userService.getUserById(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    
    // READ - Pronađi korisnika po email-u
    @GetMapping("/email/{email}")
    public ResponseEntity<UserResponse> getUserByEmail(@PathVariable String email) {
        UserResponse response = userService.getUserByEmail(email);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    
    // READ - Pronađi sve korisnike
    @GetMapping("/allUsers")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<UserResponse> response = userService.getAllUsers();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    
    // UPDATE - Ažuriraj korisnika
    @PutMapping("update/{id}")
    public ResponseEntity<UserResponse> updateUser(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest request) {
        UserResponse response = userService.updateUser(id, request);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    
    // DELETE - Obriši korisnika
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
