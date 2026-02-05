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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.Collectors;

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
    // 1. Validacija izdavaoca
    Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
    User subjectUser = userRepository.findById(dto.getSubjectUserId())
            .orElseThrow(() -> new ResourceNotFoundException("Subject user not found"));

    // 2. Učitavanje ključa i lanca roditelja
    Keystore keystore = issuerCertData.getKeystore();
    String password = cryptoService.decryptAES(keystore.getEncryptedPassword());
    
    PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
    java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
    
    if (issuerChain == null || issuerChain.length == 0) {
        throw new CertificateValidationException("Neuspešno učitavanje lanca izdavaoca.");
    }
    
    // KLJUČNA STVAR: Uzimamo X500Name direktno iz encoded forme roditelja da izbegnemo String mismatch
    X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];
    X500Name issuerName = X500Name.getInstance(issuerCertX509.getSubjectX500Principal().getEncoded());

    // 3. Generisanje podataka za novi sertifikat
    KeyPair subjectKeyPair = cryptoService.generateRSAKeyPair();
    X500Name subjectName = buildX500NameFromDto(dto);
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

    // 5. Formiranje lanca: [Novi, Roditelj, Deda...]
    java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
    newChain[0] = newCert; // Novi je na vrhu
    System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length); // Kopiramo ostatak

    // 6. Snimanje u Keystore (p12 fajl)
    String alias = serialNumber.toString();
    var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());
    
    // setKeyEntry zahteva privatni ključ novog sertifikata i kompletan lanac
    ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);
    keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

    // 7. Snimanje u bazu
    CertificateType type = isCa ? CertificateType.INTERMEDIATE : CertificateType.END_ENTITY;
    return saveCertificateEntity(newCert, subjectUser, keystore, type, issuerCertData.getSerialNumber());
}

    private Certificate validateIssuer(String issuerSerial) throws Exception {
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

        // Učitaj X509 objekat izdavaoca da bi ga proverio
        java.security.cert.Certificate[] chain = keystoreService.getCertificateChain(
            issuer.getKeystore().getId(), 
            cryptoService.decryptAES(issuer.getKeystore().getEncryptedPassword()).toCharArray(), 
            issuer.getAlias()
        );
        X509Certificate issuerX509 = (X509Certificate) chain[0];
        
        // Ako nije Root (koji je samopotpisan), proveri potpis pomoću ključa NJEGOVOG roditelja
        try {
            if (!issuer.getType().equals(CertificateType.ROOT)) {
                // Nađi sertifikat koji je izdao ovaj CA sertifikat
                Certificate parentOfIssuer = certificateRepository.findBySerialNumber(issuer.getIssuerSerialNumber())
                    .orElseThrow(() -> new Exception("Parent of issuer not found"));
                
                // Uzmi javni ključ roditelja
                PublicKey parentPubKey = ((X509Certificate) keystoreService.getCertificateChain(
                    parentOfIssuer.getKeystore().getId(),
                    cryptoService.decryptAES(parentOfIssuer.getKeystore().getEncryptedPassword()).toCharArray(),
                    parentOfIssuer.getAlias()
                )[0]).getPublicKey();
        
                // KRIPTOGRAFSKA PROVERA POTPISA
                issuerX509.verify(parentPubKey);
            } else {
                // Ako je root, proveri ga njegovim sopstvenim ključem
                issuerX509.verify(issuerX509.getPublicKey());
            }
        } catch (Exception e) {
            throw new CertificateValidationException("Digitalni potpis izdavaoca nije validan!");
        }

        checkRevocationRecursive(issuer);

        return issuer;
    }

    private void checkRevocationRecursive(Certificate cert) {
    if (cert.isRevoked()) {
        throw new CertificateValidationException("Sertifikat u lancu (" + cert.getSerialNumber() + ") je povučen!");
    }
    // Ako nije root, proveri njegovog roditelja
    if (!cert.getType().equals(CertificateType.ROOT)) {
        Certificate parent = certificateRepository.findBySerialNumber(cert.getIssuerSerialNumber())
            .orElseThrow(() -> new ResourceNotFoundException("Parent not found"));
        checkRevocationRecursive(parent);
    }
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

    public List<String> getAllCertificateSerialNumbers() {
        return certificateRepository.findAll()
                .stream()
                .map(Certificate::getSerialNumber)
                .collect(Collectors.toList());
    }

    public Certificate getCertificateBySerialNumber(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found"));
    }

    public byte[] downloadCertificateAsDER(String serialNumber) throws Exception {
        Certificate certEntity = getCertificateBySerialNumber(serialNumber);
        Keystore keystore = certEntity.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());
        
        java.security.cert.Certificate[] certChain = keystoreService.getCertificateChain(
                keystore.getId(), 
                password.toCharArray(), 
                certEntity.getAlias()
        );
        
        if (certChain == null || certChain.length == 0) {
            throw new ResourceNotFoundException("Certificate not found in keystore");
        }
        
        return certChain[0].getEncoded();
    }
}