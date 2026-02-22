package com.bezbednost.sertifikat.dto;

import lombok.Data;

@Data
public class TemplateRequestDTO {
    private String name;
    private String issuerSerialNumber;
    private String cnRegex;
    private String sanRegex;
    private long ttlDays;
    private int keyUsage;
    private String extendedKeyUsage;
}