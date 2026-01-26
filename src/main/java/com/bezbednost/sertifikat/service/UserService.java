package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.PasswordStrengthResponse;
import com.bezbednost.sertifikat.dto.RegisterRequest;
import com.bezbednost.sertifikat.dto.RegisterResponse;
import com.bezbednost.sertifikat.dto.UpdateUserRequest;
import com.bezbednost.sertifikat.dto.UserResponse;
import com.bezbednost.sertifikat.entity.ActivationToken;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.entity.UserRole;
import com.bezbednost.sertifikat.repository.ActivationTokenRepository;
import com.bezbednost.sertifikat.repository.UserRepository;
import com.bezbednost.sertifikat.validator.PasswordStrengthValidator;
import com.bezbednost.sertifikat.validator.PasswordStrengthResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private EmailService emailService;
    
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
    
    // Aktivacija naloga preko tokena
    public void activateAccount(String token) {
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
    public UserResponse getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Korisnik sa email-om " + email + " nije pronađen"));
        return mapToUserResponse(user);
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
