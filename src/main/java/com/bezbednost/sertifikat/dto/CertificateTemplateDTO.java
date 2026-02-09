package com.bezbednost.sertifikat.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateTemplateDTO {
    
    private Long id;
    private String name;
    private Long issuerId;
    private String issuerSerialNumber;
    private String cnRegex;
    private String sanRegex;
    private Integer maxTtlInDays;
    private Integer keyUsageBitmask;
    private String extendedKeyUsageOids;
    private String description;
}
