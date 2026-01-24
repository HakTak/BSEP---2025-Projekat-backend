package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.Subject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SubjectRepository extends JpaRepository<Subject, Long> {
    // Ovde možeš dodati custom metode, npr:
    Optional<Subject> findByEmail(String email);
}