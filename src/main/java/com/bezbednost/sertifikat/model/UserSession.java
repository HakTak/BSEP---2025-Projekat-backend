package com.bezbednost.sertifikat.model;

import com.bezbednost.sertifikat.entity.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_sessions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Ovo je ID sesije koji dobijamo iz Keycloak tokena ("sid" ili "jti" claim)
    // Mora biti jedinstven da ne bi duplirali istu sesiju
    @Column(nullable = false, unique = true)
    private String sessionId;

    @Column(nullable = false)
    private String ipAddress;

    @Column(nullable = false, length = 1000)
    private String userAgent;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime lastActive;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private Boolean isRevoked;

    // Povezivanje sa User tabelom
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}