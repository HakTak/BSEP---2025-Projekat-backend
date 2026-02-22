package com.bezbednost.sertifikat.dto;

import com.bezbednost.sertifikat.model.CertificateTemplate;
import lombok.Data;

@Data
public class TemplateResponseDTO {
    private Long id;
    private String name;
    private String issuerSerialNumber;
    private String issuerCommonName;
    private String cnRegex;
    private String sanRegex;
    private long ttlDays;
    private int keyUsage;
    private String extendedKeyUsage;

    public TemplateResponseDTO(CertificateTemplate t) {
        this.id = t.getId();
        this.name = t.getName();
        this.issuerSerialNumber = t.getIssuerCertificate().getSerialNumber();
        this.issuerCommonName = t.getIssuerCertificate().getCommonName();
        this.cnRegex = t.getCnRegex();
        this.sanRegex = t.getSanRegex();
        this.ttlDays = t.getTtlDays();
        this.keyUsage = t.getKeyUsage();
        this.extendedKeyUsage = t.getExtendedKeyUsage();
    }
}