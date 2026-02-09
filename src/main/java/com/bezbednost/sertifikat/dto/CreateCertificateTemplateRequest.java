package com.bezbednost.sertifikat.dto;

import lombok.Data;

@Data
public class CreateCertificateTemplateRequest {
    private String name;
    private Long issuerId;
    private String cnRegex;
    private String sanRegex;
    private Integer maxTtlInDays;
    private Integer keyUsageBitmask;
    private String extendedKeyUsageOids;
    private String description;
}