package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.Keystore;
import org.springframework.data.jpa.repository.JpaRepository;

public interface KeyStoreRepository extends JpaRepository<Keystore, Long> {
    
}