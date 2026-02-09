package com.bezbednost.sertifikat.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.CertificateTemplate;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    
    List<CertificateTemplate> findByIssuerAndActiveTrue(Certificate issuer);
    
    Optional<CertificateTemplate> findByIdAndActiveTrue(Long id);
    
    List<CertificateTemplate> findAllByActiveTrue();
    
    Optional<CertificateTemplate> findByNameAndIssuer(String name, Certificate issuer);
}
