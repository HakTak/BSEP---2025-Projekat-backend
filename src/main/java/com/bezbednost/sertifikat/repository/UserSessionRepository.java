package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByTokenId(String tokenId);

    // Pronađi sve validne sesije za korisnika (za prikaz na frontu)
    List<UserSession> findByUserIdAndIsValidTrue(Long userId);
}