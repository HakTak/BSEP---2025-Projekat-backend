package com.bezbednost.sertifikat.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordRequest {
    
    @NotBlank(message = "Token je obavezan")
    private String token;
    
    @NotBlank(message = "Nova lozinka je obavezna")
    @Size(min = 6, message = "Lozinka mora biti najmanje 6 karaktera")
    private String newPassword;
    
    @NotBlank(message = "Potvrda lozinke je obavezna")
    private String confirmPassword;
}
