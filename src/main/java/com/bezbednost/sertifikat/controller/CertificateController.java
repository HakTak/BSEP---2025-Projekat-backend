package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.CertificateDetailsDTO;
import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.service.CertificateService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/issue-root")
    public ResponseEntity<?> issueRoot(@RequestBody CertificateIssueDTO dto) {
        try {
            // U realnoj aplikaciji, ID admina bi se dobio iz Spring Security Context-a
            Long adminId = 1L; // Placeholder
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

    @GetMapping
    public ResponseEntity<?> getAll() {
        try {
            List<String> serialNumbers = certificateService.getAllCertificateSerialNumbers();
            return new ResponseEntity<>(serialNumbers, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/validate/{serialNumber}")
    public ResponseEntity<?> validate(@PathVariable String serialNumber) {
        try {
            boolean isValid = certificateService.isCertificateValid(serialNumber);
            return new ResponseEntity<>(Map.of("serialNumber", serialNumber, "isValid", isValid), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/download/{serialNumber}")
    public ResponseEntity<?> downloadCertificate(@PathVariable String serialNumber) {
        try {
            byte[] certificateData = certificateService.downloadCertificateAsDER(serialNumber);
            
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/pkix-cert"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + ".cer\"")
                    .body(certificateData);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }
    
    @GetMapping(
            value = "/check",
            produces = "application/ocsp-response"
        )
        public ResponseEntity<byte[]> check(@RequestParam String serialNumber) {

            byte[] response = null;
			try {
				response = certificateService.generateOcspResponse(serialNumber);
			} catch (Exception e) {
				e.printStackTrace();
			}

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(response);
        }
}