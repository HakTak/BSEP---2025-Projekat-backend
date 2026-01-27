package com.bezbednost.sertifikat.validator;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordStrengthResult {
    
    private Boolean valid;
    private String strength;
    
    @Builder.Default
    private List<String> errors = new ArrayList<>();
    
    @Builder.Default
    private List<String> requirements = new ArrayList<>();
    
    public void addError(String error) {
        this.errors.add(error);
        this.valid = false;
    }
    
    public void addRequirement(String requirement) {
        this.requirements.add(requirement);
    }
}
