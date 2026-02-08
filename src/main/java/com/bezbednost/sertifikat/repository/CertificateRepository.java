package com.bezbednost.sertifikat.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bezbednost.sertifikat.model.Certificate;



public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);
    List<Certificate> findByOwnerId(Long id);
}

