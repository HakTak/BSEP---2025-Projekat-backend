package com.bezbednost.sertifikat.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.Csr;



public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);
    List<Certificate> findByOwnerId(Long id);
    @Query("SELECT c FROM Certificate c WHERE c.type = CertificateType.INTERMEDIATE")
    List<Certificate> findAllCA();
    @Query("SELECT c FROM Csr c " +
    	       "JOIN Certificate cert ON c.issuerSerialNumber = cert.serialNumber " +
    	       "WHERE cert.owner.id = :userId")
    List<Csr> findCsrsBySigningCaOwner(@Param("userId") Long userId);
}

