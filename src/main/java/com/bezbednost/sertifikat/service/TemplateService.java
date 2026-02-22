package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.TemplateRequestDTO;
import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.entity.UserRole;
import com.bezbednost.sertifikat.exception.ResourceNotFoundException;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.CertificateTemplate;
import com.bezbednost.sertifikat.model.CertificateType;
import com.bezbednost.sertifikat.repository.CertificateRepository;
import com.bezbednost.sertifikat.repository.TemplateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TemplateService {

    private final TemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;

    public CertificateTemplate createTemplate(TemplateRequestDTO dto, User owner) {
        Certificate issuer = certificateRepository
                .findBySerialNumber(dto.getIssuerSerialNumber())
                .orElseThrow(() -> new ResourceNotFoundException("Issuer sertifikat nije pronađen"));

        // Issuer mora biti CA (ROOT ili INTERMEDIATE)
        if (issuer.getType() == CertificateType.END_ENTITY) {
            throw new IllegalArgumentException("End-entity sertifikat ne može biti issuer u šablonu");
        }

        // CA korisnik može koristiti samo svoje issuere
        if (owner.getRole() != UserRole.ADMIN && !issuer.getOwner().getId().equals(owner.getId())) {
            throw new IllegalArgumentException("Nemate pristup ovom issuer sertifikatu");
        }

        if (issuer.isRevoked()) {
            throw new IllegalArgumentException("Issuer sertifikat je povučen");
        }

        CertificateTemplate template = new CertificateTemplate();
        template.setName(dto.getName());
        template.setIssuerCertificate(issuer);
        template.setOwner(owner);
        template.setCnRegex(dto.getCnRegex());
        template.setSanRegex(dto.getSanRegex());
        template.setTtlDays(dto.getTtlDays());
        template.setKeyUsage(dto.getKeyUsage());
        template.setExtendedKeyUsage(dto.getExtendedKeyUsage());

        return templateRepository.save(template);
    }

    public List<CertificateTemplate> getMyTemplates(User owner) {
        return templateRepository.findByOwnerId(owner.getId());
    }

    public List<CertificateTemplate> getTemplatesForIssuer(String issuerSerialNumber) {
        return templateRepository.findByIssuerCertificate_SerialNumber(issuerSerialNumber);
    }

    public void deleteTemplate(Long id, User requester) {
        CertificateTemplate template = templateRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Šablon nije pronađen"));

        if (requester.getRole() != UserRole.ADMIN && !template.getOwner().getId().equals(requester.getId())) {
            throw new IllegalArgumentException("Nemate pravo da obrišete ovaj šablon");
        }

        templateRepository.deleteById(id);
    }
}