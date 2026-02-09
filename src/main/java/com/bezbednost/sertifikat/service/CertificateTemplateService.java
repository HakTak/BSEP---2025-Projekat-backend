package com.bezbednost.sertifikat.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.bezbednost.sertifikat.dto.CertificateTemplateDTO;
import com.bezbednost.sertifikat.dto.CreateCertificateTemplateRequest;
import com.bezbednost.sertifikat.exception.BadRequestException;
import com.bezbednost.sertifikat.exception.NotFoundException;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.CertificateTemplate;
import com.bezbednost.sertifikat.repository.CertificateRepository;
import com.bezbednost.sertifikat.repository.CertificateTemplateRepository;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CertificateTemplateService {

    private final CertificateTemplateRepository certificateTemplateRepository;
    private final CertificateRepository certificateRepository;

    /**
     * Pronalazi sve šablone za zadati Issuer sertifikat
     */
    public List<CertificateTemplateDTO> getTemplatesByIssuer(Long issuerId) {
        Certificate issuer = certificateRepository.findById(issuerId)
                .orElseThrow(() -> new NotFoundException("Issuer sertifikat nije pronađen"));

        return certificateTemplateRepository.findByIssuerAndActiveTrue(issuer)
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Pronalazi šablon po ID-u
     */
    public CertificateTemplateDTO getTemplateById(Long templateId) {
        CertificateTemplate template = certificateTemplateRepository.findByIdAndActiveTrue(templateId)
                .orElseThrow(() -> new NotFoundException("Šablon nije pronađen"));
        return convertToDTO(template);
    }

    /**
     * Pronalazi sve aktivne šablone
     */
    public List<CertificateTemplateDTO> getAllTemplates() {
        return certificateTemplateRepository.findAllByActiveTrue()
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Glavna validacijska metoda
     * Ako je templateId prosleđen, koristi šablon. U svakom slučaju, provera se pravila Issuera.
     */
    public void validateCertificateRequest(
            String commonName,
            String subjectAltNames,
            Integer ttlInDays,
            Certificate issuer,
            Long templateId,
            Integer requestedKeyUsage,
            String requestedExtendedKeyUsageOids) {

        // 1. Ako je šablon prosleđen, validuj prema šablonu
        if (templateId != null) {
            CertificateTemplate template = this.getTemplateEntity(templateId);
            
            if (template == null) {
                throw new NotFoundException("Šablon nije pronađen");
            }

            // Provera da li šablon pripada zadatom Issueru
            if (!template.getIssuer().getId().equals(issuer.getId())) {
                throw new BadRequestException("Šablon ne pripada zadatom Issueru");
            }

            // Validacija CN-a
            validateRegex(template.getCnRegex(), commonName, "Common Name ne odgovara šablonu regex izrazu");

            // Validacija SAN-a ako je prosleđen
            if (subjectAltNames != null && !subjectAltNames.isEmpty()) {
                validateRegex(template.getSanRegex(), subjectAltNames, "Subject Alternative Names ne odgovaraju šablonu regex izrazu");
            }

            // Validacija TTL-a
            if (ttlInDays > template.getMaxTtlInDays()) {
                throw new BadRequestException(
                        "Traženo trajanje (" + ttlInDays + " dana) prelazi maksimum iz šablona (" + template.getMaxTtlInDays() + " dana)"
                );
            }

            // Validacija KeyUsage i ExtendedKeyUsage ako su definisani u šablonu
            if (template.getKeyUsageBitmask() != null && requestedKeyUsage != null) {
                validateKeyUsageCompliance(template.getKeyUsageBitmask(), requestedKeyUsage);
            }

            if (template.getExtendedKeyUsageOids() != null && requestedExtendedKeyUsageOids != null) {
                validateExtendedKeyUsageCompliance(template.getExtendedKeyUsageOids(), requestedExtendedKeyUsageOids);
            }
        }

        // 2. UVEK validuj prema politici Issuera (sertifikat mora da ima sve potrebne ekstenzije)
        validateIssuerPolicy(issuer, requestedKeyUsage, requestedExtendedKeyUsageOids);
    }

    /**
     * Validacija regex izraza za CN ili SAN
     */
    private void validateRegex(String regex, String value, String errorMessage) {
        try {
            if (!Pattern.matches(regex, value)) {
                throw new BadRequestException(errorMessage + ": " + regex);
            }
        } catch (PatternSyntaxException e) {
            throw new BadRequestException("Nevalidan regex u šablonu: " + e.getMessage());
        }
    }

    /**
     * Validacija KeyUsage: traženi KU ne sme sadržati više bita nego što Issuer dozvoljava
     */
    private void validateKeyUsageCompliance(Integer templateKeyUsageBitmask, Integer requestedKeyUsage) {
        // Traženi bitmask mora biti subset šablona (traženi & ~template == 0)
        if ((requestedKeyUsage & ~templateKeyUsageBitmask) != 0) {
            throw new BadRequestException(
                    "Traženi KeyUsage prevazilazi dozvoljene vrednosti iz šablona"
            );
        }
    }

    /**
     * Validacija ExtendedKeyUsage: provera da li su svi traženi OID-i dozvoljeni
     */
    private void validateExtendedKeyUsageCompliance(String templateOids, String requestedOids) {
        String[] allowedOids = templateOids.split(",");
        String[] requested = requestedOids.split(",");

        for (String requestedOid : requested) {
            boolean isAllowed = false;
            for (String allowedOid : allowedOids) {
                if (allowedOid.trim().equals(requestedOid.trim())) {
                    isAllowed = true;
                    break;
                }
            }
            if (!isAllowed) {
                throw new BadRequestException(
                        "OID " + requestedOid.trim() + " nije dozvoljen prema šablonu"
                );
            }
        }
    }

    /**
     * Validacija prema politici Issuera
     * Provera da li Issuer sertifikat omogućava tražene ekstenzije
     */
    private void validateIssuerPolicy(Certificate issuer, Integer requestedKeyUsage, String requestedExtendedKeyUsageOids) {
        // Ako Issuer ima definisanu KeyUsage politiku
        if (issuer.getKeyUsageBitmask() != null && requestedKeyUsage != null) {
            validateKeyUsageCompliance(issuer.getKeyUsageBitmask(), requestedKeyUsage);
        }

        // Ako Issuer ima definisanu ExtendedKeyUsage politiku
        if (issuer.getExtendedKeyUsageOids() != null && requestedExtendedKeyUsageOids != null) {
            validateExtendedKeyUsageCompliance(issuer.getExtendedKeyUsageOids(), requestedExtendedKeyUsageOids);
        }
    }

    /**
     * Konverzija entiteta u DTO
     */
    private CertificateTemplateDTO convertToDTO(CertificateTemplate template) {
        return new CertificateTemplateDTO(
                template.getId(),
                template.getName(),
                template.getIssuer().getId(),
                template.getIssuer().getSerialNumber(),
                template.getCnRegex(),
                template.getSanRegex(),
                template.getMaxTtlInDays(),
                template.getKeyUsageBitmask(),
                template.getExtendedKeyUsageOids(),
                template.getDescription()
        );
    }

    public CertificateTemplateDTO createTemplate(CreateCertificateTemplateRequest request) {
    Certificate issuer = certificateRepository.findById(request.getIssuerId())
            .orElseThrow(() -> new NotFoundException("Issuer nije pronađen"));

    if (certificateTemplateRepository.findByNameAndIssuer(request.getName(), issuer).isPresent()) {
    throw new BadRequestException("Šablon sa ovim imenom već postoji za ovog Issuera");
}
    // Validacija regex-a
    validateRegexPattern(request.getCnRegex());
    validateRegexPattern(request.getSanRegex());

    CertificateTemplate template = new CertificateTemplate();
    template.setName(request.getName());
    template.setIssuer(issuer);
    template.setCnRegex(request.getCnRegex());
    template.setSanRegex(request.getSanRegex());
    template.setMaxTtlInDays(request.getMaxTtlInDays());
    template.setKeyUsageBitmask(request.getKeyUsageBitmask());
    template.setExtendedKeyUsageOids(request.getExtendedKeyUsageOids());
    template.setDescription(request.getDescription());
    template.setActive(true);

    CertificateTemplate saved = certificateTemplateRepository.save(template);
    return convertToDTO(saved);
    }

    private void validateRegexPattern(String regex) {
        if (regex == null || regex.isEmpty()) {
            throw new BadRequestException("Regex ne može biti prazan");
        }
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new BadRequestException("Nevalidan regex: " + e.getMessage());
        }
    }

    public CertificateTemplate getTemplateEntity(Long templateId) {
    return certificateTemplateRepository.findByIdAndActiveTrue(templateId)
            .orElseThrow(() -> new NotFoundException("Šablon nije pronađen ili je neaktivan"));
}

    public CertificateTemplateDTO updateTemplate(Long templateId, CreateCertificateTemplateRequest request) {
        CertificateTemplate template = certificateTemplateRepository.findByIdAndActiveTrue(templateId)
                .orElseThrow(() -> new NotFoundException("Šablon nije pronađen"));

        Certificate issuer = certificateRepository.findById(request.getIssuerId())
                .orElseThrow(() -> new NotFoundException("Issuer nije pronađen"));

        // Validacija regex-a
        validateRegexPattern(request.getCnRegex());
        validateRegexPattern(request.getSanRegex());

        template.setName(request.getName());
        template.setIssuer(issuer);
        template.setCnRegex(request.getCnRegex());
        template.setSanRegex(request.getSanRegex());
        template.setMaxTtlInDays(request.getMaxTtlInDays());
        template.setKeyUsageBitmask(request.getKeyUsageBitmask());
        template.setExtendedKeyUsageOids(request.getExtendedKeyUsageOids());
        template.setDescription(request.getDescription());

        CertificateTemplate updated = certificateTemplateRepository.save(template);
        return convertToDTO(updated);
    }

    public void deleteTemplate(Long templateId) {
        CertificateTemplate template = certificateTemplateRepository.findById(templateId)
                .orElseThrow(() -> new NotFoundException("Šablon nije pronađen"));
        
        // Logičko brisanje (soft delete)
        template.setActive(false);
        certificateTemplateRepository.save(template);
    }
}

