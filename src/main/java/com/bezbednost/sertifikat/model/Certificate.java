package com.bezbednost.sertifikat.model;

import java.math.BigInteger;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "certificates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Certificate {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Subject fields
    @Column(nullable = false)
    private String commonName;           
    private String organization;         
    private String organizationalUnit;   
    private String country;              
    private String state;                
    private String locality;             

    @Column(nullable = false)
    private Instant issuedAt;            // certificate issuance timestamp

    @Column(nullable = false)
    private Instant expiresAt;           // certificate expiration

    @Column(nullable = false)
    private String publicKey;            // public key as string from CSR

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;        // ROOT / INTERMEDIATE / END_ENTITY

    private Long issuerId;               // parent certificate (null for root)

    @Column(nullable = false)
    private boolean revoked;             // revocation status
    
    @Column(nullable = false, unique = true)
    private BigInteger serialNumber; // unique X.509 serial number
}
