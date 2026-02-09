package com.bezbednost.sertifikat.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
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
import java.util.Date;

@Component
public class CertificateFactory {

    public X509Certificate createCertificate(
        X500Name subject, X500Name issuer,
        PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
        ZonedDateTime validFrom, ZonedDateTime validTo,
        BigInteger serialNumber,
        boolean isCa, int keyUsage, String issuerSerial) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, 
                serialNumber,
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant()),
                subject, 
                subjectPublicKey);

        // Važno: BasicConstraints mora biti kritična ekstenzija za CA
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        if (!isCa) {

            String ocspUrl = "https://localhost:8443/api/certificates/check";

            AccessDescription ocspAccess = new AccessDescription(AccessDescription.id_ad_ocsp,
            		new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    ocspUrl
            ));
            
            String issuerUrl = "https://localhost:8443/api/certificates/download/" + issuerSerial;
            AccessDescription caIssuerAccess = new AccessDescription(
                    AccessDescription.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, issuerUrl)
            );

            AuthorityInformationAccess aia = new AuthorityInformationAccess(new AccessDescription[]{ocspAccess, caIssuerAccess});
            
            certBuilder.addExtension(
                    Extension.authorityInfoAccess,
                    false,
                    aia
            );
        }

        // Koristimo SHA256WithRSA
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

        // Validacija prema šablonu i Issuer politici
        templateService.validateCertificateRequest(
                commonName,
                sanValue,
                ttlInDays,
                issuerCertificate,
                templateId,
                keyUsage,
                extendedKeyUsageOids
        );

        // Nakon validacije, kreiraj sertifikat
        return createCertificate(subject, issuer, subjectPublicKey, issuerPrivateKey,
                validFrom, validTo, serialNumber, isCa, keyUsage, issuerSerial);
    }
}
