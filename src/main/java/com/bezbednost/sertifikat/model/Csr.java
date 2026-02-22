package com.bezbednost.sertifikat.model;

import java.time.LocalDateTime;

import com.bezbednost.sertifikat.entity.User;
import jakarta.persistence.*;
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
	    private String email;             // L

		@Column(columnDefinition = "TEXT", nullable = false)
		private String publicKey;         // public key as string

	    @Column(nullable = false)
	    private LocalDateTime expiresAt;           // requested certificate expiration

	    @Column(nullable = false)
	    private LocalDateTime issuedAt;
	    
	    @Column(nullable = false)
	    private String issuerSerialNumber;       // CA that will sign

	    @Enumerated(EnumType.STRING)
	    private CsrStatus status;            // PENDING / APPROVED  / REJECTED

	@ManyToOne
	@JoinColumn(name = "user_id")
	private User user;

}
