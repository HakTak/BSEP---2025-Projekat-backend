package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    List<CertificateTemplate> findByOwnerId(Long ownerId);
    List<CertificateTemplate> findByIssuerCertificate_SerialNumber(String serialNumber);
}