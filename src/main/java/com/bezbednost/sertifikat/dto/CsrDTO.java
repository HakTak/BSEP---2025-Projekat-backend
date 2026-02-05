package com.bezbednost.sertifikat.dto;

import java.time.LocalDateTime;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CsrDTO {
	@NotBlank
    public String csrPem;

    @NotNull
    public Long intermediateCaId;

    @NotNull
    public LocalDateTime expiresAt; // certificate desired expiration
}
