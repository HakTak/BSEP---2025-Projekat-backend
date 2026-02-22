package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.UserSessionDTO;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.entity.UserRole;
import com.bezbednost.sertifikat.model.UserSession;
import com.bezbednost.sertifikat.repository.UserRepository;
import com.bezbednost.sertifikat.repository.UserSessionRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserSessionService {

    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;

    public UserSessionService(UserSessionRepository userSessionRepository, UserRepository userRepository) {
        this.userSessionRepository = userSessionRepository;
        this.userRepository = userRepository;
    }

    public boolean isSessionRevoked(String sessionId) {
        return userSessionRepository.findBySessionId(sessionId)
                .map(UserSession::getIsRevoked)
                .orElse(false);
    }

    public List<UserSessionDTO> getUserSessions(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Korisnik nije pronađen"));

        return userSessionRepository.findAllByUserId(user.getId()).stream()
                .map(session -> UserSessionDTO.builder()
                        .sessionId(session.getSessionId())
                        .ipAddress(session.getIpAddress())
                        .userAgent(session.getUserAgent())
                        .createdAt(session.getCreatedAt())
                        .lastActive(session.getLastActive())
                        .expiresAt(session.getExpiresAt())
                        .isRevoked(session.getIsRevoked())
                        .build())
                .collect(Collectors.toList());
    }

    @Transactional
    public void revokeSession(String sessionId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        final String adminEmail = email;

        User user = userRepository.findByEmail(adminEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + adminEmail));

        UserSession session = userSessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> new RuntimeException("Sesija nije pronađena"));

        if (!session.getUser().equals(user)) {
            throw new IllegalStateException("Ovo nije vasa sesija!");
        }

        session.setIsRevoked(true);
        userSessionRepository.save(session);
    }

    @Transactional
    public void revokeActiveSession(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        final String userEmail = email;

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + userEmail));

        UserSession session = userSessionRepository.findBySessionId(jwt.getClaimAsString("sid"))
                .orElseThrow(() -> new RuntimeException("Sesija nije pronađena"));

        session.setIsRevoked(true);
        userSessionRepository.save(session);
    }

    // Ovu metodu koristi Filter
    @Transactional
    public void trackUserSession(String email, String sessionId, String ipAddress, String userAgent, Jwt jwt) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            user = User.builder()
                    .email(email)
                    .firstName(jwt.getClaimAsString("given_name"))
                    .lastName(jwt.getClaimAsString("family_name"))
                    .organization("Unknown")
                    .password("")
                    .role(UserRole.USER)
                    .enabled(true)
                    .build();
            user = userRepository.save(user);
        }

        Instant exp = jwt.getExpiresAt();
        LocalDateTime expiresAt = (exp != null)
                ? LocalDateTime.ofInstant(exp, ZoneId.systemDefault())
                : LocalDateTime.now().plusDays(30); // Fallback ako token nema exp

        Optional<UserSession> existingSession = userSessionRepository.findBySessionId(sessionId);

        if (existingSession.isPresent()) {
            UserSession session = existingSession.get();
            session.setLastActive(LocalDateTime.now());
            session.setExpiresAt(expiresAt);

            if (!session.getIpAddress().equals(ipAddress)) {
                session.setIpAddress(ipAddress);
            }
            userSessionRepository.save(session);
        } else {
            UserSession newSession = UserSession.builder()
                    .sessionId(sessionId)
                    .user(user)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .createdAt(LocalDateTime.now())
                    .lastActive(LocalDateTime.now())
                    .expiresAt(expiresAt)
                    .isRevoked(false)
                    .build();
            userSessionRepository.save(newSession);
        }
    }

}