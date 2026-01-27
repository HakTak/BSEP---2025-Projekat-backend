package com.bezbednost.sertifikat.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordStrengthResponse {
    private Boolean valid;
    private String strength;
    private List<String> errors;
    private List<String> requirements;
}
