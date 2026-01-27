package com.bezbednost.sertifikat.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    
    @Email(message = "Email mora biti validan")
    @NotBlank(message = "Email je obavezan")
    private String email;
    
    @NotBlank(message = "Lozinka je obavezna")
    @Size(min = 6, message = "Lozinka mora biti najmanje 6 karaktera")
    private String password;
    
    @NotBlank(message = "Potvrda lozinke je obavezna")
    private String confirmPassword;
    
    @NotBlank(message = "Ime je obavezno")
    private String firstName;
    
    @NotBlank(message = "Prezime je obavezno")
    private String lastName;
    
    @NotBlank(message = "Organizacija je obavezna")
    private String organization;
}
