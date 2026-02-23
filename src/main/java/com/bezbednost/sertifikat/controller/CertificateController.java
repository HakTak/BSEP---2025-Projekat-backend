package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.CertificateDetailsDTO;
import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.dto.CsrDTO;
import com.bezbednost.sertifikat.dto.RevocationRequest;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
import com.bezbednost.sertifikat.service.CertificateService;
import com.bezbednost.sertifikat.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final UserService userService;
    private final AuditLogger auditLogger;

    // ----------------------------------------------------------------
    // Izdavanje Root sertifikata
    // ----------------------------------------------------------------
    @PostMapping("/issue-root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> issueRoot(
            @RequestBody CertificateIssueDTO dto,
            HttpServletRequest httpRequest) {

        String ip       = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            Certificate cert = certificateService.issueRootCertificate(dto);
            auditLogger.logSuccess(AuditEventType.CERT_ISSUE_ROOT, userEmail, ip,
                    "Root sertifikat izdat. SN=" + cert.getSerialNumber()
                            + " | CN=" + cert.getCommonName());
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CERT_ISSUE_ROOT_FAIL, userEmail, ip,
                    "Neuspesno izdavanje root sertifikata: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Izdavanje Intermediate sertifikata
    // ----------------------------------------------------------------
    @PostMapping("/issue-intermediate")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> issueCertificate(
            @RequestBody CertificateIssueDTO dto,
            HttpServletRequest httpRequest) {

        String ip        = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            Certificate cert = certificateService.issueCertificate(dto);
            auditLogger.logSuccess(AuditEventType.CERT_ISSUE_INTERMEDIATE, userEmail, ip,
                    "Intermediate/EE sertifikat izdat. SN=" + cert.getSerialNumber()
                            + " | CN=" + cert.getCommonName()
                            + " | IssuerSN=" + dto.getIssuerSerialNumber());
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CERT_ISSUE_INTERMEDIATE_FAIL, userEmail, ip,
                    "Neuspesno izdavanje intermediate sertifikata: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Odobravanje CSR zahteva (izdavanje EE sertifikata)
    // ----------------------------------------------------------------
    @PostMapping("/approve-csr/{csrId}")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> approveCsr(
            @PathVariable Long csrId,
            HttpServletRequest httpRequest) {

        String ip        = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            Certificate cert = certificateService.issueE2ECertificate(csrId);
            auditLogger.logSuccess(AuditEventType.CSR_APPROVE, userEmail, ip,
                    "CSR odobren i EE sertifikat izdat. CSR_ID=" + csrId
                            + " | SN=" + cert.getSerialNumber());
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CSR_APPROVE_FAIL, userEmail, ip,
                    "Neuspesno odobravanje CSR-a. CSR_ID=" + csrId + ": " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Pregled svih sertifikata
    // ----------------------------------------------------------------
    @GetMapping("/getAll")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getAll(HttpServletRequest httpRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");
        if (email == null) email = jwt.getClaimAsString("preferred_username");
        if (email == null) throw new IllegalStateException("Email nije pronađen u tokenu!");

        final String subjectEmail = email;
        User user = userService.getUserByEmail(subjectEmail);
        try {
            List<CertificateDetailsDTO> dtos = certificateService.getAll(user)
                    .stream()
                    .map(CertificateDetailsDTO::new)
                    .toList();
            auditLogger.logSuccess(AuditEventType.CERT_VIEW_ALL, subjectEmail,
                    getClientIp(httpRequest),
                    "Korisnik pregledao listu sertifikata. Broj=" + dtos.size());
            return new ResponseEntity<>(dtos, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // ----------------------------------------------------------------
    // Validacija sertifikata
    // ----------------------------------------------------------------
    @GetMapping("/validate/{serialNumber}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> validate(
            @PathVariable String serialNumber,
            HttpServletRequest httpRequest) {

        try {
            boolean isValid = certificateService.isCertificateValid(serialNumber);
            auditLogger.logSuccess(AuditEventType.CERT_VALIDATE, extractEmail(),
                    getClientIp(httpRequest),
                    "Validacija sertifikata. SN=" + serialNumber + " | valid=" + isValid);
            return new ResponseEntity<>(Map.of("serialNumber", serialNumber, "isValid", isValid), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Preuzimanje sertifikata
    // ----------------------------------------------------------------
    @GetMapping("/download/{serialNumber}")
    public ResponseEntity<?> downloadCertificate(
            @PathVariable String serialNumber,
            HttpServletRequest httpRequest) {

        String ip        = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            byte[] certificateData = certificateService.downloadCertificateAsDER(serialNumber);
            auditLogger.logSuccess(AuditEventType.CERT_DOWNLOAD, userEmail, ip,
                    "Sertifikat preuzet. SN=" + serialNumber);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/pkix-cert"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + ".cer\"")
                    .body(certificateData);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CERT_DOWNLOAD_FAIL, userEmail, ip,
                    "Neuspesno preuzimanje sertifikata. SN=" + serialNumber + ": " + e.getMessage());
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // OCSP check (ne loguje se pojedinacno – automatski zahtev)
    // ----------------------------------------------------------------
    @PostMapping(value = "/check",
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> checkRevokeStatus(@RequestBody byte[] requestBytes) {
        try {
            byte[] response = certificateService.handleOcspRequest(requestBytes);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(response);
        } catch (Exception e) {
            try {
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType("application/ocsp-response"))
                        .body(new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null).getEncoded());
            } catch (Exception fatal) {
                return ResponseEntity.status(500).build();
            }
        }
    }

    // ----------------------------------------------------------------
    // Povlacenje sertifikata
    // ----------------------------------------------------------------
    @PutMapping("/revoke")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revoke(
            @RequestBody RevocationRequest revocationRequest,
            HttpServletRequest httpRequest) {

        String ip        = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            Certificate cert = certificateService.revoke(
                    revocationRequest.getSerialNumber(), revocationRequest.getRevocationCode());
            auditLogger.logSuccess(AuditEventType.CERT_REVOKE, userEmail, ip,
                    "Sertifikat povucen. SN=" + revocationRequest.getSerialNumber()
                            + " | kod=" + revocationRequest.getRevocationCode());
            return ResponseEntity.ok().body(new CertificateDetailsDTO(cert));
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CERT_REVOKE_FAIL, userEmail, ip,
                    "Neuspesno povlacenje sertifikata. SN=" + revocationRequest.getSerialNumber()
                            + ": " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Podnošenje CSR zahteva
    // ----------------------------------------------------------------
    @PostMapping("/submitCsr")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> submitCsr(
            @RequestBody CsrDTO csrDTO,
            HttpServletRequest httpRequest) {

        String ip        = getClientIp(httpRequest);
        String userEmail = extractEmail();
        try {
            Object result = certificateService.submitCsr(csrDTO);
            auditLogger.logSuccess(AuditEventType.CSR_SUBMIT, userEmail, ip,
                    "CSR podnet. IssuerSN=" + csrDTO.getIssuerSerialNumber());
            return ResponseEntity.ok().body(result);
        } catch (Exception e) {
            auditLogger.logFailure(AuditEventType.CSR_SUBMIT_FAIL, userEmail, ip,
                    "Neuspesno podnošenje CSR-a: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // ----------------------------------------------------------------
    // Pomocni GET endpointi (ne loguju se kao posebni audit dogadjaji)
    // ----------------------------------------------------------------
    @GetMapping("/getAllCA")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getAllCA() {
        List<CertificateDetailsDTO> dtos = certificateService.getAllCA()
                .stream().map(CertificateDetailsDTO::new).toList();
        return new ResponseEntity<>(dtos, HttpStatus.OK);
    }

    @GetMapping("/getAllEE")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getAllEE() {
        List<CertificateDetailsDTO> dtos = certificateService.getAllEE()
                .stream().map(CertificateDetailsDTO::new).toList();
        return new ResponseEntity<>(dtos, HttpStatus.OK);
    }

    @GetMapping("/getAllCACsr")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> getAllCACsr(HttpServletRequest httpRequest) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt jwt = (Jwt) authentication.getPrincipal();

            String email = jwt.getClaimAsString("email");
            if (email == null) email = jwt.getClaimAsString("preferred_username");
            if (email == null) throw new IllegalStateException("Email nije pronađen u tokenu!");

            final String subjectEmail = email;
            User user = userService.getUserByEmail(subjectEmail);
            List<?> result = certificateService.getAllCACsr(user.getId());
            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    // ----------------------------------------------------------------
    // Pomocne metode
    // ----------------------------------------------------------------
    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }

    private String extractEmail() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
                String email = jwt.getClaimAsString("email");
                if (email == null) email = jwt.getClaimAsString("preferred_username");
                return email != null ? email : "UNKNOWN";
            }
        } catch (Exception ignored) { }
        return "ANONYMOUS";
    }
}