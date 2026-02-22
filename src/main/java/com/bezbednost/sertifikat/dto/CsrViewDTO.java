package com.bezbednost.sertifikat.dto;

import java.time.LocalDateTime;

import com.bezbednost.sertifikat.model.CsrStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CsrViewDTO {
	private Long id;
	private String commonName;           // CN
    private String organization;         // O
    private String organizationalUnit;   // OU
    private String country;              // C
    private String email;    
    private String publicKey; 
    private LocalDateTime expiresAt;  
    private LocalDateTime issuedAt;
    private String issuerSerialNumber;
    private CsrStatus status;   
}
