package com.bezbednost.sertifikat.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.bezbednost.sertifikat.dto.CertificateTemplateDTO;
import com.bezbednost.sertifikat.service.CertificateTemplateService;

import java.util.List;

@RestController
@RequestMapping("/api/certificate-templates")
@RequiredArgsConstructor
public class CertificateTemplateController {

    private final CertificateTemplateService certificateTemplateService;

    /**
     * GET /api/certificate-templates/issuer/{issuerId}
     * Pronalazi sve šablone za zadati Issuer
     */
    @GetMapping("/issuer/{issuerId}")
    public ResponseEntity<List<CertificateTemplateDTO>> getTemplatesByIssuer(@PathVariable Long issuerId) {
        List<CertificateTemplateDTO> templates = certificateTemplateService.getTemplatesByIssuer(issuerId);
        return ResponseEntity.ok(templates);
    }

    /**
     * GET /api/certificate-templates/{templateId}
     * Pronalazi šablon po ID-u
     */
    @GetMapping("/{templateId}")
    public ResponseEntity<CertificateTemplateDTO> getTemplateById(@PathVariable Long templateId) {
        CertificateTemplateDTO template = certificateTemplateService.getTemplateById(templateId);
        return ResponseEntity.ok(template);
    }

    /**
     * GET /api/certificate-templates
     * Pronalazi sve aktivne šablone
     */
    @GetMapping
    public ResponseEntity<List<CertificateTemplateDTO>> getAllTemplates() {
        List<CertificateTemplateDTO> templates = certificateTemplateService.getAllTemplates();
        return ResponseEntity.ok(templates);
    }
}
