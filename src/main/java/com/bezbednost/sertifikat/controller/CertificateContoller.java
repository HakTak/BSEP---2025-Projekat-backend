package com.bezbednost.sertifikat.controller;

import java.math.BigInteger;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bezbednost.sertifikat.service.CertificateService;

@RestController
@RequestMapping("/api/certificate")
public class CertificateContoller {
	private CertificateService ocspService;

    @GetMapping(
        value = "/check",
        produces = "application/ocsp-response"
    )
    public ResponseEntity<byte[]> check(@RequestParam BigInteger serialNumber) {

        byte[] response = ocspService.generateOcspResponse(serialNumber);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/ocsp-response"))
                .body(response);
    }
}
