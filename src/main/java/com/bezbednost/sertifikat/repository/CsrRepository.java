package com.bezbednost.sertifikat.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bezbednost.sertifikat.model.Csr;

public interface CsrRepository extends JpaRepository<Csr, Long> {

}
