package com.bezbednost.sertifikat.dto;

import com.bezbednost.sertifikat.model.CertificateType;
import lombok.Data;
import java.time.ZonedDateTime;
import java.util.List;

@Data
public class CertificateIssueDTO {
    //Podaci o sablonu
    private Long templateId;

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
    private String issuerSerialNumber;

    private boolean ca;
    private List<Integer> keyUsage;
}