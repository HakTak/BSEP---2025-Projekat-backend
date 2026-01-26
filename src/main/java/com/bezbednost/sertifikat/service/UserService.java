package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.RegisterRequest;
import com.bezbednost.sertifikat.dto.RegisterResponse;
import com.bezbednost.sertifikat.dto.UpdateUserRequest;
import com.bezbednost.sertifikat.dto.UserResponse;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.entity.UserRole;
import com.bezbednost.sertifikat.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // CREATE - Registracija
    public RegisterResponse register(RegisterRequest request) {
        // Validacija da su lozinke iste
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Lozinke se ne poklapaju");
        }
        
        // Validacija da email nije već registrovan
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email je već registrovan");
        }
        
        // Kreiramo novog korisnika
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .organization(request.getOrganization())
                .role(UserRole.USER)
                .enabled(true)
                .build();
        
        userRepository.save(user);
        
        return new RegisterResponse("Registracija uspešna", request.getEmail());
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
