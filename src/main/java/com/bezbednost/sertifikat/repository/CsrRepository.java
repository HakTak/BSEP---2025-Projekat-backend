package com.bezbednost.sertifikat.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bezbednost.sertifikat.model.Csr;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CsrRepository extends JpaRepository<Csr, Long> {
    @Query("SELECT c FROM Csr c " +
            "JOIN Certificate cert ON c.issuerSerialNumber = cert.serialNumber " +
            "WHERE cert.owner.id = :userId")
    List<Csr> findCsrsBySigningCaOwner(@Param("userId") Long userId);
}
