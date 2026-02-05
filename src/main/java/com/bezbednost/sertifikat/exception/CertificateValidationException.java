package com.bezbednost.sertifikat.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class CertificateValidationException extends RuntimeException {
    public CertificateValidationException(String message) {
        super(message);
    }
}