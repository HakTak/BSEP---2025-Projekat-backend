package com.bezbednost.sertifikat.repository;

import com.bezbednost.sertifikat.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    // Pronađi sve sesije za određenog korisnika (po User ID-u iz baze)
    List<UserSession> findAllByUserId(Long userId);

    // Pronađi sesiju po njenom javnom ID-u (onom iz tokena)
    Optional<UserSession> findBySessionId(String sessionId);

    // Pronađi sve aktivne sesije za korisnika
    List<UserSession> findAllByUserIdAndIsRevokedFalse(Long userId);
}