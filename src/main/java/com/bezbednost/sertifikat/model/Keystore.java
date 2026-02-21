package com.bezbednost.sertifikat.model;

import com.bezbednost.sertifikat.entity.User;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Keystore {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 512)
    private String encryptedPassword;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}