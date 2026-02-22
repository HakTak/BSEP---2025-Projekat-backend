package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.TemplateRequestDTO;
import com.bezbednost.sertifikat.dto.TemplateResponseDTO;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.model.CertificateTemplate;
import com.bezbednost.sertifikat.service.TemplateService;
import com.bezbednost.sertifikat.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
@RequiredArgsConstructor
public class TemplateController {

    private final TemplateService templateService;
    private final UserService userService;

    @PostMapping
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> createTemplate(@RequestBody TemplateRequestDTO dto) {
        try {
            User user = getCurrentUser();
            CertificateTemplate created = templateService.createTemplate(dto, user);
            return new ResponseEntity<>(new TemplateResponseDTO(created), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/my")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> getMyTemplates() {
        try {
            User user = getCurrentUser();
            List<TemplateResponseDTO> result = templateService.getMyTemplates(user)
                    .stream().map(TemplateResponseDTO::new).toList();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/issuer/{serialNumber}")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> getTemplatesForIssuer(@PathVariable String serialNumber) {
        try {
            List<TemplateResponseDTO> result = templateService.getTemplatesForIssuer(serialNumber)
                    .stream().map(TemplateResponseDTO::new).toList();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> deleteTemplate(@PathVariable Long id) {
        try {
            User user = getCurrentUser();
            templateService.deleteTemplate(id, user);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String email = jwt.getClaimAsString("email");
        if (email == null) email = jwt.getClaimAsString("preferred_username");
        return userService.getUserByEmail(email);
    }
}