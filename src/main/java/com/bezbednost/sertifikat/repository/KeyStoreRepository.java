package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.Keystore;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KeyStoreRepository extends JpaRepository<Keystore, Long> {
    Optional<Keystore> findByUser_Id(Long id);
}