package com.bezbednost.sertifikat.dto;

import com.bezbednost.sertifikat.entity.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String organization;
    private UserRole role;
    private Boolean enabled;
}
