package com.bezbednost.sertifikat.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;
import com.bezbednost.sertifikat.model.Certificate;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyPurposeId;

@Component
public class CertificateFactory {

    /**
     * Metoda za kreiranje sertifikata bez template validacije
     */
    public X509Certificate createCertificate(
            X500Name subject, X500Name issuer,
            PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom, ZonedDateTime validTo,
            BigInteger serialNumber,
            boolean isCa, int keyUsage, String issuerSerial,
            String sanValue, String extendedKeyUsageOids) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, 
                serialNumber,
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant()),
                subject, 
                subjectPublicKey);

        // BasicConstraints - mora biti kritična za CA
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        
        // 🔧 Dodaj SAN ako je prosleđen i nije CA
        if (sanValue != null && !sanValue.isEmpty() && !isCa) {
            try {
                GeneralName[] gns = parseSANValue(sanValue);
                GeneralNames generalNames = new GeneralNames(gns);
                certBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);
            } catch (Exception e) {
                throw new IllegalArgumentException("Nevalidan SAN format: " + sanValue, e);
            }
        }
        
        // 🔧 Dodaj Extended Key Usage ako je prosleđen
        if (extendedKeyUsageOids != null && !extendedKeyUsageOids.isEmpty()) {
            try {
                ExtendedKeyUsage eku = parseExtendedKeyUsageOids(extendedKeyUsageOids);
                certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);
            } catch (Exception e) {
                throw new IllegalArgumentException("Nevalidan Extended Key Usage OID: " + extendedKeyUsageOids, e);
            }
        }

        // AIA za non-CA sertifikate
        if (!isCa) {
            String ocspUrl = "https://localhost:8443/api/certificates/check";
            AccessDescription ocspAccess = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
            
            String issuerUrl = "https://localhost:8443/api/certificates/download/" + issuerSerial;
            AccessDescription caIssuerAccess = new AccessDescription(
                    AccessDescription.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, issuerUrl));

            AuthorityInformationAccess aia = new AuthorityInformationAccess(
                    new AccessDescription[]{ocspAccess, caIssuerAccess});
            
            certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);
        }

        // Potpisuj sertifikat
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(issuerPrivateKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Overload metoda sa template validacijom
     */
    public X509Certificate createCertificateWithTemplate(
            X500Name subject, X500Name issuer,
            PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom, ZonedDateTime validTo,
            BigInteger serialNumber,
            boolean isCa, int keyUsage, String issuerSerial,
            Certificate issuerCertificate, Long templateId,
            String commonName, String sanValue, Integer ttlInDays,
            String extendedKeyUsageOids,
            CertificateTemplateService templateService) throws Exception {

        // 1. Validacija prema šablonu
        templateService.validateCertificateRequest(
                commonName,
                sanValue,
                ttlInDays,
                issuerCertificate,
                templateId,
                keyUsage,
                extendedKeyUsageOids
        );

        // 2. Kreiraj sertifikat sa template podacima
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, 
                serialNumber,
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant()),
                subject, 
                subjectPublicKey);

        // BasicConstraints i KeyUsage
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        
        // Dodaj Subject Alternative Names ako je prosleđen
        if (sanValue != null && !sanValue.isEmpty() && !isCa) {
            try {
                GeneralName[] gns = parseSANValue(sanValue);
                GeneralNames generalNames = new GeneralNames(gns);
                certBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);
            } catch (Exception e) {
                throw new IllegalArgumentException("Nevalidan SAN format: " + sanValue, e);
            }
        }
        
        // Dodaj Extended Key Usage ako je prosleđen
        if (extendedKeyUsageOids != null && !extendedKeyUsageOids.isEmpty()) {
            try {
                ExtendedKeyUsage eku = parseExtendedKeyUsageOids(extendedKeyUsageOids);
                certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);
            } catch (Exception e) {
                throw new IllegalArgumentException("Nevalidan Extended Key Usage OID: " + extendedKeyUsageOids, e);
            }
        }

        // AIA za non-CA sertifikate
        if (!isCa) {
            String ocspUrl = "https://localhost:8443/api/certificates/check";
            AccessDescription ocspAccess = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
            
            String issuerUrl = "https://localhost:8443/api/certificates/download/" + issuerSerial;
            AccessDescription caIssuerAccess = new AccessDescription(
                    AccessDescription.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, issuerUrl));

            AuthorityInformationAccess aia = new AuthorityInformationAccess(
                    new AccessDescription[]{ocspAccess, caIssuerAccess});
            
            certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);
        }

        // Potpisuj sertifikat
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(issuerPrivateKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Helper metoda - Parsira SAN vrijednosti (DNS, e-mail, IP)
     */
    private GeneralName[] parseSANValue(String sanValue) {
        String[] parts = sanValue.split(",");
        GeneralName[] gns = new GeneralName[parts.length];
        
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            
            // Provjeri tip: e-mail, DNS, ili IP
            if (part.contains("@")) {
                gns[i] = new GeneralName(GeneralName.rfc822Name, part);
            } else if (isValidIP(part)) {
                gns[i] = new GeneralName(GeneralName.iPAddress, part);
            } else {
                // Default DNS
                gns[i] = new GeneralName(GeneralName.dNSName, part);
            }
        }
        return gns;
    }

    /**
     * Helper metoda - Parsira Extended Key Usage OID-e
     */
    private ExtendedKeyUsage parseExtendedKeyUsageOids(String oidsString) {
    String[] oids = oidsString.split(",");
    List<KeyPurposeId> keyPurposeIds = new ArrayList<>();
    
    for (String oid : oids) {
        try {
            // Pretvaramo string OID u ASN1ObjectIdentifier, a zatim u KeyPurposeId
            ASN1ObjectIdentifier asn1Oid = new ASN1ObjectIdentifier(oid.trim());
            keyPurposeIds.add(KeyPurposeId.getInstance(asn1Oid));
        } catch (Exception e) {
            throw new IllegalArgumentException("Nevalidan OID: " + oid.trim(), e);
        }
    }
    
    // Konstruktor sada prihvata niz KeyPurposeId objekata
    return new ExtendedKeyUsage(keyPurposeIds.toArray(new KeyPurposeId[0]));
}

    /**
     * Helper metoda - Provjeri da li je vrijednost validna IP adresa
     */
    private boolean isValidIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

}  // ✅ Zatvarajuća zagrada klase