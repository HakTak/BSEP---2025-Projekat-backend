package com.bezbednost.sertifikat.model;

import com.bezbednost.sertifikat.entity.User;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class CertificateTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id")
    private User owner;

    private String cnRegex;
    private String sanRegex;
    private long ttlDays;
    private int keyUsage;
    private String extendedKeyUsage;
}