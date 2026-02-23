package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.*;
import com.bezbednost.sertifikat.entity.ActivationToken;
import com.bezbednost.sertifikat.entity.PasswordResetToken;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.entity.UserRole;
import com.bezbednost.sertifikat.utils.PasswordGenerator;
import com.bezbednost.sertifikat.repository.ActivationTokenRepository;
import com.bezbednost.sertifikat.repository.PasswordResetTokenRepository;
import com.bezbednost.sertifikat.repository.UserRepository;
import com.bezbednost.sertifikat.validator.PasswordStrengthValidator;
import com.bezbednost.sertifikat.validator.PasswordStrengthResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private ActivationTokenRepository activationTokenRepository;
    
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordGenerator passwordGenerator;

    @Autowired
    private KeycloakService keycloakService;

    @Value("${app.activation.token.expiry}")
    private long tokenExpiryTime;
    
    // CREATE - Registracija sa email aktivacijom
    public RegisterResponse register(RegisterRequest request) {
        // Validacija da su lozinke iste
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Lozinke se ne poklapaju");
        }
        
        // Validacija jačine lozinke
        PasswordStrengthValidator validator = PasswordStrengthValidator.builder()
                .password(request.getPassword())
                .build();
        PasswordStrengthResult validationResult = validator.validateBasic();
        
        if (!validationResult.getValid()) {
            String errors = String.join(", ", validationResult.getErrors());
            throw new IllegalArgumentException("Lozinka nije dovoljno jaka: " + errors);
        }
        
        // Validacija da email nije već registrovan
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email je već registrovan");
        }
        
        // Kreiramo novog korisnika sa enabled = false
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .organization(request.getOrganization())
                .role(UserRole.USER)
                .enabled(false) // Nalog nije aktivan dok se ne aktivira kroz email
                .build();
        
        userRepository.save(user);
        
        // Kreiramo aktivacioni token
        String activationTokenStr = UUID.randomUUID().toString();
        ActivationToken activationToken = ActivationToken.builder()
                .token(activationTokenStr)
                .user(user)
                .expiryDate(LocalDateTime.now().plusSeconds(tokenExpiryTime / 1000))
                .used(false)
                .build();
        
        activationTokenRepository.save(activationToken);
        
        // Slanje aktivacionog emaila
        try {
            emailService.sendActivationEmail(user.getEmail(), user.getFirstName(), activationTokenStr);
        } catch (Exception e) {
            userRepository.delete(user);
            throw new RuntimeException("Greška pri slanju aktivacionog emaila. Pokušajte ponovo.");
        }
        
        return new RegisterResponse("Registracija uspešna! Proverite email za aktivacioni link.", request.getEmail());
    }

    public RegisterResponse registerCAUser(CreateCARequest request) {
        // 1. Validacija emaila
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Korisnik sa ovim email-om već postoji.");
        }

        // 2. Generisanje jake nasumične lozinke
        String tempPassword = passwordGenerator.generateStrongPassword();

        // 3. Kreiranje lokalnog korisnika
        User user = User.builder()
                .email(request.getEmail())
                // U lokalnoj bazi čuvamo hash lozinke (iako se auth radi preko Keycloaka, dobra je praksa imati sync)
                .password(passwordEncoder.encode(tempPassword))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .organization(request.getOrganization())
                .role(UserRole.CA_USER) // <--- CA ROLA
                .enabled(true) // Odmah je aktivan
                .build();

        userRepository.save(user);

        // 4. Kreiranje korisnika u Keycloaku
        try {
            keycloakService.createCAUser(
                    request.getEmail(),
                    request.getFirstName(),
                    request.getLastName(),
                    request.getOrganization(),
                    tempPassword
            );
        } catch (Exception e) {
            // Rollback lokalne baze ako Keycloak pukne
            userRepository.delete(user);
            throw new RuntimeException("Greška pri kreiranju CA korisnika u Keycloaku: " + e.getMessage());
        }

        // 5. Slanje emaila sa lozinkom
        try {
            emailService.sendCACredentials(request.getEmail(), request.getFirstName(), tempPassword);
        } catch (Exception e) {
            // Ovde ne radimo rollback, ali logujemo grešku.
            // Admin može ručno da resetuje lozinku ili ponovi proces ako je kritično.
            System.err.println("Greska pri slanju mejla CA korisniku: " + e.getMessage());
        }

        return new RegisterResponse("CA Korisnik uspešno kreiran. Kredencijali su poslati na email.", request.getEmail());
    }
    
    // Aktivacija naloga preko tokena
    public User activateAccount(String token) {
        ActivationToken activationToken = activationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Nevalidan aktivacioni token"));
        
        // Provera da li je token već korišten
        if (activationToken.getUsed()) {
            throw new IllegalArgumentException("Token je već korišten");
        }
        
        // Provera da li je token istekao
        if (LocalDateTime.now().isAfter(activationToken.getExpiryDate())) {
            throw new IllegalArgumentException("Aktivacioni token je istekao");
        }
        
        // Aktiviramo nalog
        User user = activationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        
        // Označavamo token kao korišten
        activationToken.setUsed(true);
        activationToken.setUsedAt(LocalDateTime.now());
        activationTokenRepository.save(activationToken);
        return user;
    }

    public void changeCaUserPassword(ChangePasswordRequest request) {

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Lozinke se ne poklapaju");
        }

        PasswordStrengthValidator validator = PasswordStrengthValidator.builder()
                .password(request.getNewPassword())
                .build();

        PasswordStrengthResult result = validator.validate();

        if (!result.getValid()) {
            throw new IllegalArgumentException(String.join(", ", result.getErrors()));
        }

        // 1. Uzimamo Authentication i kastujemo u JWT
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String mustChangePassword = jwt.getClaimAsString("mustChangePassword");
        System.out.println("mustChangePassword claim: " + mustChangePassword);

        if ("false".equals(mustChangePassword)) {
            throw new IllegalStateException("Ne mozete vise da menjate sifru!");
        }

        // 2. Izvlačimo email (privremena promenljiva)
        String tempEmail = jwt.getClaimAsString("email");

        // Fallback logika (ako nema emaila, probaj username)
        if (tempEmail == null) {
            tempEmail = jwt.getClaimAsString("preferred_username");
        }

        if (tempEmail == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String email = tempEmail;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + email));

        // 5. Promeni lozinku u Keycloak-u
        keycloakService.updatePassword(email, request.getNewPassword());

        // 6. Update lokalno
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // 7. SET mustChangePassword = false u Keycloak-u
        keycloakService.updateUserAttribute(email, "mustChangePassword", "false");

    }

    
    // FORGOT PASSWORD - Zahtev za reset lozinke
    public void forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa ovim emailom nije pronadjen"));
        
        // Obrišemo stare reset tokene ako postoje
        passwordResetTokenRepository.findByUserAndUsedFalse(user).ifPresent(passwordResetTokenRepository::delete);
        
        // Kreiramo novi reset token
        String resetTokenStr = UUID.randomUUID().toString();
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(resetTokenStr)
                .user(user)
                .expiryDate(LocalDateTime.now().plusSeconds(tokenExpiryTime / 1000))
                .used(false)
                .build();
        
        passwordResetTokenRepository.save(resetToken);
        
        // Slanje reset emaila
        try {
            emailService.sendPasswordResetEmail(user.getEmail(), user.getFirstName(), resetTokenStr);
        } catch (Exception e) {
            throw new RuntimeException("Greska pri slanju reset emaila. Pokusajte ponovo.");
        }
    }
    
    // RESET PASSWORD - Resetovanje lozinke
    public void resetPassword(ResetPasswordRequest request) {
        // Validacija da su lozinke iste
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Lozinke se ne poklapaju");
        }
        
        // Validacija jačine lozinke
        PasswordStrengthValidator validator = PasswordStrengthValidator.builder()
                .password(request.getNewPassword())
                .build();
        PasswordStrengthResult validationResult = validator.validateBasic();
        
        if (!validationResult.getValid()) {
            String errors = String.join(", ", validationResult.getErrors());
            throw new IllegalArgumentException("Lozinka nije dovoljno jaka: " + errors);
        }
        
        // Pronalaženje i validacija tokena
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new IllegalArgumentException("Nevalidan reset token"));
        
        if (resetToken.getUsed()) {
            throw new IllegalArgumentException("Token je vec koristen");
        }
        
        if (LocalDateTime.now().isAfter(resetToken.getExpiryDate())) {
            throw new IllegalArgumentException("Reset token je istekao");
        }
        
        // Resetovanje lozinke u postgreu
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // 2. Promeni lozinku u keyclock
        keycloakService.updatePassword(user.getEmail(), request.getNewPassword());

        // Označavanje tokena kao korišten
        resetToken.setUsed(true);
        resetToken.setUsedAt(LocalDateTime.now());
        passwordResetTokenRepository.save(resetToken);
    }
    
    // Provera jačine lozinke
    public PasswordStrengthResponse checkPasswordStrength(String password) {
        PasswordStrengthValidator validator = PasswordStrengthValidator.builder()
                .password(password)
                .build();
        PasswordStrengthResult result = validator.validate();
        
        return PasswordStrengthResponse.builder()
                .valid(result.getValid())
                .strength(result.getStrength())
                .errors(result.getErrors())
                .build();
    }
    
    // READ - Pronađi korisnika po ID-u
    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa ID-om " + id + " nije pronađen"));
        return mapToUserResponse(user);
    }
    
    // READ - Pronađi korisnika po email-u
    public UserResponse getUserDtoByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa email-om " + email + " nije pronađen"));
        return mapToUserResponse(user);
    }

    public User getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa email-om " + email + " nije pronađen"));
        return user;
    }
    
    // READ - Pronađi sve korisnike
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }
    
    // UPDATE - Ažuriraj korisnika
    public UserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa ID-om " + id + " nije pronađen"));
        
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setOrganization(request.getOrganization());
        
        userRepository.save(user);
        return mapToUserResponse(user);
    }
    
    // DELETE - Obriši korisnika
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa ID-om " + id + " nije pronađen"));
        userRepository.delete(user);
    }
    
    // Pomoćna metoda za mapiranje
    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .organization(user.getOrganization())
                .role(user.getRole())
                .enabled(user.getEnabled())
                .build();
    }
}
