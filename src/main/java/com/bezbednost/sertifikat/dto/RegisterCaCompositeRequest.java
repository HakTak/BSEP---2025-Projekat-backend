package com.bezbednost.sertifikat.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class RegisterCaCompositeRequest {

    @Valid
    @NotNull
    private CreateCARequest userRequest; // Podaci za korisnika (email, password...)

    @Valid
    @NotNull
    private CertificateIssueDTO certificateRequest; // Podaci za sertifikat (CN, O, OU...)
}