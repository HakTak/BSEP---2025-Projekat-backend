package com.bezbednost.sertifikat.dto;

import lombok.Data;
import java.time.ZonedDateTime;
import java.util.List;

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
    
    private boolean isCa; // Da li je sertifikat CA
    private List<Integer> keyUsagelist; // Lista KeyUsage vrednosti (npr. 0x04 za digitalSignature)
    private Integer keyUsageBitmask; // Bitmaska za KeyUsage (ako se koristi umesto liste) /*
    /*  
        KeyUsage.digitalSignature        = 0x80 (bit 0)
        KeyUsage.nonRepudiation          = 0x40 (bit 1)
        KeyUsage.keyEncipherment         = 0x20 (bit 2)
        KeyUsage.dataEncipherment        = 0x10 (bit 3)
        KeyUsage.keyAgreement            = 0x08 (bit 4)
        KeyUsage.keyCertSign             = 0x04 (bit 5)
        KeyUsage.cRLSign                 = 0x02 (bit 6)
    */
   private Long templateId; // ID šablona koji se koristi za validaciju (opciono)
   private String subjectAltName;     // Subject Alternative Name (DNS, e-mail, IP) - OPCIONO
   private String extendedKeyUsageOids; // Extended Key Usage OID-i (npr. "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")


}