package com.bezbednost.sertifikat.validator;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordStrengthValidator {
    
    private String password;
    
    // Validacija jačine lozinke
    public PasswordStrengthResult validate() {
        PasswordStrengthResult result = new PasswordStrengthResult();
        
        if (password == null || password.isEmpty()) {
            result.setValid(false);
            result.addError("Lozinka ne sme biti prazna");
            return result;
        }
        
        // Provera da li sadrži razmake
        if (password.contains(" ")) {
            result.addError("Lozinka ne sme sadržavati razmake");
        }
        
        // Provera minimalne dužine
        if (password.length() < 8) {
            result.addError("Lozinka mora imati najmanje 8 karaktera (trenutno: " + password.length() + ")");
        }
        
        // Provera da li sadrži velika slova
        if (!password.matches(".*[A-Z].*")) {
            result.addError("Lozinka mora sadržavati barem jedno VELIKO slovo (A-Z)");
        }
        
        // Provera da li sadrži mala slova
        if (!password.matches(".*[a-z].*")) {
            result.addError("Lozinka mora sadržavati barem jedno malo slovo (a-z)");
        }
        
        // Provera da li sadrži brojeve
        if (!password.matches(".*[0-9].*")) {
            result.addError("Lozinka mora sadržavati barem jedan broj (0-9)");
        }
        
        // Provera da li sadrži specijalne simbole
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>?/].*")) {
            result.addError("Lozinka mora sadržavati barem jedan specijalni simbol (!@#$%^&*...)");
        }
        
        // Ako nema grešaka, lozinka je validna
        if (result.getErrors().isEmpty()) {
            result.setValid(true);
            result.setStrength("VEOMA JAKA");
        }
        
        return result;
    }
    
    // Provera samo osnovnih zahteva (za register)
    public PasswordStrengthResult validateBasic() {
        PasswordStrengthResult result = new PasswordStrengthResult();
        
        if (password == null || password.isEmpty()) {
            result.setValid(false);
            result.addError("Lozinka ne sme biti prazna");
            return result;
        }
        
        if (password.contains(" ")) {
            result.addError("Lozinka ne sme sadržavati razmake");
        }
        
        if (password.length() < 8) {
            result.addError("Lozinka mora imati najmanje 8 karaktera");
        }
        
        if (!password.matches(".*[A-Z].*")) {
            result.addError("Lozinka mora sadržavati barem jedno VELIKO slovo");
        }
        
        if (!password.matches(".*[a-z].*")) {
            result.addError("Lozinka mora sadržavati barem jedno malo slovo");
        }
        
        if (!password.matches(".*[0-9].*")) {
            result.addError("Lozinka mora sadržavati barem jedan broj");
        }
        
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>?/].*")) {
            result.addError("Lozinka mora sadržavati barem jedan specijalni simbol");
        }
        
        if (result.getErrors().isEmpty()) {
            result.setValid(true);
            result.setStrength("VEOMA JAKA");
        }
        
        return result;
    }
}
