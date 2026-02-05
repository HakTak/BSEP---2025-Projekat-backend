package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.entity.*;
import com.bezbednost.sertifikat.exception.CertificateValidationException;
import com.bezbednost.sertifikat.exception.ResourceNotFoundException;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.CertificateType;
import com.bezbednost.sertifikat.model.Keystore;
import com.bezbednost.sertifikat.repository.CertificateRepository;
import com.bezbednost.sertifikat.repository.UserRepository;
import com.bezbednost.sertifikat.repository.KeyStoreRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.stereotype.Service;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final KeyStoreRepository keystoreRepository;
    private final CryptoService cryptoService;
    private final KeystoreService keystoreService;
    private final CertificateFactory certificateFactory;

    @Transactional
    public Certificate issueRootCertificate(Long adminId, CertificateIssueDTO dto) throws Exception {
        User admin = userRepository.findById(adminId).orElseThrow(() -> new ResourceNotFoundException("Admin not found"));
        if (admin.getRole() != UserRole.ADMIN) {
            throw new SecurityException("Only admins can issue root certificates.");
        }

        String password = cryptoService.generateRandomPassword();
        Keystore keystore = new Keystore();
        keystore.setEncryptedPassword(cryptoService.encryptAES(password));
        keystoreRepository.save(keystore);
        
        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectAndIssuer = buildX500NameFromDto(dto);
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        X509Certificate cert = certificateFactory.createCertificate(
                subjectAndIssuer, subjectAndIssuer,
                keyPair.getPublic(), keyPair.getPrivate(),
                dto.getValidFrom(), dto.getValidTo(),
                serialNumber, true, KeyUsage.keyCertSign | KeyUsage.cRLSign
        );

        String alias = serialNumber.toString();
        var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());
        ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        return saveCertificateEntity(cert, admin, keystore, CertificateType.ROOT, serialNumber.toString());
    }

    @Transactional
    public Certificate issueCertificate(CertificateIssueDTO dto) throws Exception {
        // 1. Validacija
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
        User subjectUser = userRepository.findById(dto.getSubjectUserId()).orElseThrow(() -> new ResourceNotFoundException("Subject user not found"));

        // 2. Učitavanje podataka o izdavaocu
        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());
        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
        
        if (issuerChain == null || issuerChain.length == 0) {
            throw new ResourceNotFoundException(" PRAZAN LANAC SERTIFIKATA ZA IZDAVAOCA !");
        }   
        X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];

        // 3. Generisanje podataka za novi sertifikat
        KeyPair subjectKeyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectName = buildX500NameFromDto(dto);
        X500Name issuerName = new X500Name(issuerCertX509.getSubjectX500Principal().getName());
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        
        boolean isCa = subjectUser.getRole() == UserRole.ADMIN || subjectUser.getRole() == UserRole.CA_USER;
        int keyUsage = isCa ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature | KeyUsage.keyEncipherment;

        // 4. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate(
            subjectName, issuerName,
            subjectKeyPair.getPublic(), issuerPrivateKey,
            dto.getValidFrom(), dto.getValidTo(),
            serialNumber, isCa, keyUsage
        );
        
        // 5. Čuvanje u keystore
        String alias = serialNumber.toString();
        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
        newChain[0] = newCert;
        System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);
        
        var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());
        ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);
        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        // 6. Čuvanje u bazu
        CertificateType type = isCa ? CertificateType.INTERMEDIATE : CertificateType.END_ENTITY;
        return saveCertificateEntity(newCert, subjectUser, keystore, type, issuerCertData.getSerialNumber());
    }

    private Certificate validateIssuer(String issuerSerial) {
        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerial)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer certificate not found."));

        if (issuer.isRevoked()) {
            throw new CertificateValidationException("Issuer certificate is revoked.");
        }
        if (issuer.getValidTo().isBefore(LocalDateTime.now())) {
            throw new CertificateValidationException("Issuer certificate has expired.");
        }
        if (issuer.getType() == CertificateType.END_ENTITY) {
            throw new CertificateValidationException("End-entity certificates cannot issue new certificates.");
        }
        return issuer;
    }

    private Certificate saveCertificateEntity(X509Certificate cert, User owner, Keystore keystore, CertificateType type, String issuerSerial) {
        Certificate certEntity = new Certificate();
        certEntity.setSerialNumber(cert.getSerialNumber().toString());
        certEntity.setAlias(cert.getSerialNumber().toString());
        certEntity.setSubjectDN(cert.getSubjectX500Principal().getName());
        certEntity.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setType(type);
        certEntity.setOwner(owner);
        certEntity.setKeystore(keystore);
        certEntity.setIssuerSerialNumber(issuerSerial);
        return certificateRepository.save(certEntity);
    }
    
    private X500Name buildX500NameFromDto(CertificateIssueDTO dto) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, dto.getCommonName());
        builder.addRDN(BCStyle.O, dto.getOrganization());
        builder.addRDN(BCStyle.OU, dto.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, dto.getCountry());
        builder.addRDN(BCStyle.EmailAddress, dto.getEmail());
        return builder.build();
    }

    public boolean isCertificateValid(String serialNumber) {
    Certificate cert = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new ResourceNotFoundException("Certificate not found"));
    
    if (cert.isRevoked()) return false;
    if (cert.getValidTo().isBefore(LocalDateTime.now())) return false;
    
    // Ovdje bi se u realnom sistemu proveravao i ceo lanac do Root-a
    return true;
}

    
}