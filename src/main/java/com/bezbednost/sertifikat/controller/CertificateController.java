package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.dto.CertificateDetailsDTO;
import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.dto.CsrDTO;
import com.bezbednost.sertifikat.dto.RevocationRequest;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.service.CertificateService;

import com.bezbednost.sertifikat.service.UserService;
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

    @PostMapping("/issue-root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> issueRoot(@RequestBody CertificateIssueDTO dto) {
        try {
            com.bezbednost.sertifikat.model.Certificate cert = certificateService.issueRootCertificate(dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/issue-intermediate")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> issueCertificate(@RequestBody CertificateIssueDTO dto) {
        try {
            com.bezbednost.sertifikat.model.Certificate cert = certificateService.issueCertificate(dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/approve-csr/{csrId}")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> approveCsr(@PathVariable Long csrId) {
        try {
            Certificate cert = certificateService.issueE2ECertificate(csrId);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/getAll")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getAll() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User user = userService.getUserByEmail(subjectEmail);
        try {
            List<CertificateDetailsDTO> dtos =
                    certificateService.getAll(user)
                            .stream()
                            .map(cert -> new CertificateDetailsDTO(cert
                            ))
                            .toList();
            return new ResponseEntity<>(dtos, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    

    @GetMapping("/validate/{serialNumber}")
    @PreAuthorize("isAuthenticated()")
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
    
    @PostMapping(
    	    value = "/check",
    	    consumes = "application/ocsp-request",
    	    produces = "application/ocsp-response"
    	)
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
        
     @PutMapping("/revoke")
     @PreAuthorize("isAuthenticated()")
     public ResponseEntity<?> revoke(@RequestBody RevocationRequest revocationRequest){
    	 return ResponseEntity.ok().body(certificateService.revoke(revocationRequest.getSerialNumber(), revocationRequest.getRevocationCode()));
     }

     @PostMapping("/submitCsr")
     @PreAuthorize("hasRole('USER')")
     public ResponseEntity<?> submitCsr(@RequestBody CsrDTO csrDTO){
    	 try {
			return ResponseEntity.ok().body(certificateService.submitCsr(csrDTO));
		} catch (Exception e) {
			 return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		}
     }
     @GetMapping("/getAllCA")
     @PreAuthorize("hasRole('USER')")
     public ResponseEntity<?> getAllCA(){
    	 List<CertificateDetailsDTO> dtos =
    			 certificateService.getAllCA()
    			 .stream()
    			 .map(cert -> new CertificateDetailsDTO(cert
    					 ))
    			 .toList();
    	 return new ResponseEntity<>(dtos, HttpStatus.OK);
     }
     
     @GetMapping("/getAllEE")
     @PreAuthorize("hasRole('USER')")
     public ResponseEntity<?> getAllEE(){
    	 List<CertificateDetailsDTO> dtos =
    			 certificateService.getAllEE()
    			 .stream()
    			 .map(cert -> new CertificateDetailsDTO(cert
    					 ))
    			 .toList();
    	 return new ResponseEntity<>(dtos, HttpStatus.OK);
     }

    @GetMapping("/getAllCACsr")
    @PreAuthorize("hasRole('CA_USER') || hasRole('ADMIN')")
    public ResponseEntity<?> getAllCACsr(){
        try{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("AUTH: " + authentication);
            System.out.println("AUTH CLASS: " + authentication.getClass().getName());

            org.springframework.security.oauth2.jwt.Jwt jwt = (Jwt) authentication.getPrincipal();
            System.out.println("JWT OK");

            String email = jwt.getClaimAsString("email");
            System.out.println("EMAIL: " + email);

            if (email == null) {
                email = jwt.getClaimAsString("preferred_username");
                System.out.println("PREFERRED_USERNAME: " + email);
            }

            if (email == null) {
                throw new IllegalStateException("Email nije pronađen u tokenu!");
            }

            final String subjectEmail = email;
            User user = userService.getUserByEmail(subjectEmail);
            System.out.println("USER: " + user);
            System.out.println("USER ID: " + user.getId());

            List<?> result = certificateService.getAllCACsr(user.getId());
            System.out.println("RESULT SIZE: " + result.size());

            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch(Exception e){
            System.out.println("EXCEPTION: " + e.getMessage());
            e.printStackTrace();
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }
}