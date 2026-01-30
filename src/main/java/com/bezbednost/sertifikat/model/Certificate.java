package com.bezbednost.sertifikat.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

import com.bezbednost.sertifikat.entity.User;

@Entity
@Data
public class Certificate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String serialNumber;

    @Column(unique = true, nullable = false)
    private String alias;

    @Column(nullable = false)
    private String issuerSerialNumber;

    @Column(nullable = false, length = 1024)
    private String subjectDN;

    @Column(nullable = false)
    private LocalDateTime validFrom;

    @Column(nullable = false)
    private LocalDateTime validTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id")
    private User owner;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "keystore_id")
    private Keystore keystore;

    private boolean revoked = false;
    private LocalDateTime revocationDate;
    private String revocationReason;
}