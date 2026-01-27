package com.bezbednost.sertifikat.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {
    
    @NotBlank(message = "Ime je obavezno")
    private String firstName;
    
    @NotBlank(message = "Prezime je obavezno")
    private String lastName;
    
    @NotBlank(message = "Organizacija je obavezna")
    private String organization;
}
