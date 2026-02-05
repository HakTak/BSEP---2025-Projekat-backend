package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.CertificateDetailsDTO;
import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.service.CertificateService;

import lombok.RequiredArgsConstructor;

import org.bouncycastle.asn1.x509.Certificate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/issue-root")
    public ResponseEntity<?> issueRoot(@RequestBody CertificateIssueDTO dto) {
        try {
            // U realnoj aplikaciji, ID admina bi se dobio iz Spring Security Context-a
            Long adminId = 1L; 
            com.bezbednost.sertifikat.model.Certificate cert = certificateService.issueRootCertificate(adminId, dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/issue")
    public ResponseEntity<?> issueCertificate(@RequestBody CertificateIssueDTO dto) {
        try {
            com.bezbednost.sertifikat.model.Certificate cert = certificateService.issueCertificate(dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}