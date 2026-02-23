package com.bezbednost.sertifikat.dto;

import lombok.Data;

@Data
public class ShareEntryDTO {
    private Long id;
    private String siteName;
    private String userName;
    private String owner;
    private String encryptedPassword;
}