package com.bezbednost.sertifikat.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordRequest {
    
    @Email(message = "Email mora biti validan")
    @NotBlank(message = "Email je obavezan")
    private String email;
}
