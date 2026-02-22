package com.bezbednost.sertifikat.dto;

import lombok.Data;
import java.time.LocalDateTime;

import com.bezbednost.sertifikat.model.Certificate;

@Data
public class CertificateDetailsDTO {
    private Long id;
    private String serialNumber;
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
    private String issuerSerialNumber;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private String publicKey;
    private String type;
    private boolean isRevoked;
    private int revocationCode;

    public CertificateDetailsDTO(Certificate cert) {
        this.id = cert.getId();
        this.serialNumber = cert.getSerialNumber();
        this.commonName = cert.getCommonName();
        this.organization = cert.getOrganization();
        this.organizationalUnit = cert.getOrganizationalUnit();
        this.country = cert.getCountry();
        this.email = cert.getEmail();
        this.issuerSerialNumber = cert.getIssuerSerialNumber();
        this.validFrom = cert.getValidFrom();
        this.validTo = cert.getValidTo();
        this.type = cert.getType().name();
        this.isRevoked = cert.isRevoked();
        this.revocationCode = cert.getRevocationCode();
        this.publicKey = cert.getPublicKey();
    }
}