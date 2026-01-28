package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.entity.User;
import com.bezbednost.sertifikat.model.UserSession;
import com.bezbednost.sertifikat.repository.UserSessionRepository;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.List;

public class UserSessionService {
    @Autowired
    private UserSessionRepository sessionRepository;

    // Poziva se prilikom LOGINA
    public void createSession(User user, String tokenId, String ipAddress, String rawUserAgent) {
        UserSession session = new UserSession();
        session.setJwtTokenId(tokenId) ;
        session.setUser(user);
        session.setIpAddress(ipAddress);

        // XSS ZAŠTITA: Čistimo User-Agent string pre upisa u bazu
        // Haker može poslati <script> kroz User-Agent header
        String safeDeviceInfo = Jsoup.clean(rawUserAgent, Safelist.none());
        // Skratimo ako je predugačko (opciono, ali dobra praksa)
        if (safeDeviceInfo.length() > 255) safeDeviceInfo = safeDeviceInfo.substring(0, 255);

        session.setDeviceInfo(safeDeviceInfo);
        session.setLastActivity(LocalDateTime.now());
        session.setValid(true);

        sessionRepository.save(session);
    }

    // Praćenje aktivnosti (ažurira vreme)
    public void updateLastActivity(String tokenId) {
        sessionRepository.findByTokenId(tokenId).ifPresent(session -> {
            session.setLastActivity(LocalDateTime.now());
            sessionRepository.save(session);
        });
    }

    // Opoziv sesije (Logout)
    public void revokeSession(String tokenId) {
        sessionRepository.findByTokenId(tokenId).ifPresent(session -> {
            session.setValid(false);
            sessionRepository.save(session);
        });
    }

    public List<UserSession> getActiveSessions(Long userId) {
        return sessionRepository.findByUserIdAndIsValidTrue(userId);
    }

    public boolean isSessionValid(String tokenId) {
        return sessionRepository.findByTokenId(tokenId)
                .map(UserSession::isValid)
                .orElse(false);
    }
}
