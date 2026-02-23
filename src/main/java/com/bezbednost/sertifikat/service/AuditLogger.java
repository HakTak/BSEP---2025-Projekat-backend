package com.bezbednost.sertifikat.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Centralizovani servis za audit logovanje.
 *
 * Svaki log zapis sadrzi:
 *   - datum/vreme (ISO 8601, definisano u logback-spring.xml)
 *   - eventId      – UUID za jedinstvenu identifikaciju dogadjaja
 *   - eventType    – tip dogadjaja (AuditEventType)
 *   - userId       – email ili ID korisnika koji je uzrokovao dogadjaj
 *   - ipAddress    – IP adresa klijenta
 *   - result       – SUCCESS ili FAILURE
 *   - poruka       – slobodan opis dogadjaja
 *
 * Ovo pokriva zahteve za neporecivost iz specifikacije i smernica.
 */
@Service
public class AuditLogger {

    // Koristimo poseban logger "AUDIT" koji je definisan u logback-spring.xml
    // i pise iskljucivo u audit.log fajl.
    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    // ----------------------------------------------------------------
    // Javni API
    // ----------------------------------------------------------------

    /**
     * Loguj uspesni bezbednosni dogadjaj.
     *
     * @param eventType  Tip dogadjaja
     * @param userId     Email ili ID korisnika (null ako nije autentifikovan)
     * @param ipAddress  IP adresa klijenta
     * @param details    Slobodan opis (bez osetljivih podataka!)
     */
    public void logSuccess(AuditEventType eventType, String userId, String ipAddress, String details) {
        writeLog(eventType, userId, ipAddress, "SUCCESS", details);
    }

    /**
     * Loguj neuspesni / odbijeni bezbednosni dogadjaj.
     *
     * @param eventType  Tip dogadjaja
     * @param userId     Email ili ID korisnika (null ako nije autentifikovan)
     * @param ipAddress  IP adresa klijenta
     * @param details    Opis greske (bez stack trace-a sa osetljivim podacima)
     */
    public void logFailure(AuditEventType eventType, String userId, String ipAddress, String details) {
        writeLog(eventType, userId, ipAddress, "FAILURE", details);
    }

    /**
     * Genericki log – koristiti kada zelimo manuelno zadati rezultat.
     */
    public void log(AuditEventType eventType, String userId, String ipAddress, boolean success, String details) {
        writeLog(eventType, userId, ipAddress, success ? "SUCCESS" : "FAILURE", details);
    }

    // ----------------------------------------------------------------
    // Privatna implementacija
    // ----------------------------------------------------------------

    private void writeLog(AuditEventType eventType,
                          String userId,
                          String ipAddress,
                          String result,
                          String details) {
        try {
            // MDC se koristi da bi Logback mogao da ubaci polja u pattern
            // Format u audit.log: datum | eventId | eventType | userId | ip | result | poruka
            MDC.put("eventId",    UUID.randomUUID().toString());
            MDC.put("eventType",  eventType.name());
            MDC.put("userId",     userId     != null ? userId     : "ANONYMOUS");
            MDC.put("ipAddress",  ipAddress  != null ? ipAddress  : "UNKNOWN");
            MDC.put("result",     result);

            log.info(details);

        } finally {
            // Uvek cisti MDC da ne bi doslo do curenja podataka
            // izmedju razlicitih zahteva (thread-reuse u Spring-u)
            MDC.remove("eventId");
            MDC.remove("eventType");
            MDC.remove("userId");
            MDC.remove("ipAddress");
            MDC.remove("result");
        }
    }
}