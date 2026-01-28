package com.bezbednost.sertifikat.model;

import com.bezbednost.sertifikat.entity.User;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_sessions")
@Data
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String jwtTokenId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id",  nullable = false)
    private User user;

    private String ipAddress;

    private String deviceInfo;

    private LocalDateTime lastActivity;

    private boolean isValid = true;
}
