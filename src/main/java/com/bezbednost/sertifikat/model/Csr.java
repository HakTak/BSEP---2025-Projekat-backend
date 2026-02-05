package com.bezbednost.sertifikat.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "csrs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Csr {
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;

	    // X500Name subject fields
	    @Column(nullable = false)
	    private String commonName;           // CN

	    private String organization;         // O
	    private String organizationalUnit;   // OU
	    private String country;              // C
	    private String state;                // ST
	    private String locality;             // L

	    @Lob
	    @Column(nullable = false)
	    private String publicKey;         // public key as string

	    @Column(nullable = false)
	    private Instant expiresAt;           // requested certificate expiration

	    @Column(nullable = false)
	    private Instant issuedAt;
	    
	    @Column(nullable = false)
	    private Long intermediateCaId;       // CA that will sign

	    @Enumerated(EnumType.STRING)
	    private CsrStatus status;            // PENDING / APPROVED  / REJECTED
}
