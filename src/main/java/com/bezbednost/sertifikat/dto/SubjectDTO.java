package com.bezbednost.sertifikat.dto;

import lombok.Data;

@Data
public class SubjectDTO {
    private String email;
    private String commonName;
    private String organization;
}