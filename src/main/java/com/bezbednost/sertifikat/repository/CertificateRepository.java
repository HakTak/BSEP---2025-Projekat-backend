package com.bezbednost.sertifikat.repository;

import java.math.BigInteger;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bezbednost.sertifikat.model.Certificate;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
	Certificate findBySerialNumber(BigInteger serialNumber);
}
