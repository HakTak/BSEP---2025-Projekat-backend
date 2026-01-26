package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.entity.ActivationToken;
import com.bezbednost.sertifikat.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ActivationTokenRepository extends JpaRepository<ActivationToken, Long> {
    Optional<ActivationToken> findByToken(String token);
    Optional<ActivationToken> findByUserAndUsedFalse(User user);
}
