package com.bezbednost.sertifikat.dto;

import lombok.Data;
import java.time.ZonedDateTime;

@Data
public class CertificateIssueDTO {
    // Podaci o subjektu
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    // Period važenja
    private ZonedDateTime validFrom;
    private ZonedDateTime validTo;
    
    // Za non-root sertifikate
    private String issuerSerialNumber; // Serijski broj sertifikata koji potpisuje
    private Long subjectUserId;      // ID korisnika za koga se izdaje
}