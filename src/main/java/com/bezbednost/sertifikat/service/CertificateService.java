package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.dto.CsrDTO;
import com.bezbednost.sertifikat.dto.CsrViewDTO;
import com.bezbednost.sertifikat.entity.*;
import com.bezbednost.sertifikat.exception.CertificateValidationException;
import com.bezbednost.sertifikat.exception.ResourceNotFoundException;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.CertificateType;
import com.bezbednost.sertifikat.model.Csr;
import com.bezbednost.sertifikat.model.CsrStatus;
import com.bezbednost.sertifikat.model.Keystore;
import com.bezbednost.sertifikat.repository.CertificateRepository;
import com.bezbednost.sertifikat.repository.CsrRepository;
import com.bezbednost.sertifikat.repository.UserRepository;
import com.bezbednost.sertifikat.repository.KeyStoreRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
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
    private final CsrRepository csrRepository;
    
    @Transactional
    public Certificate issueRootCertificate(CertificateIssueDTO dto) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String adminEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User admin = userRepository.findByEmail(adminEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + adminEmail));

        Keystore keystore;
        String password;
        Optional<Keystore> optionalKeystore = keystoreRepository.findByUser_Id(admin.getId());
        if(optionalKeystore.isPresent()) {
            keystore = optionalKeystore.get();
            password = cryptoService.decryptAES(keystore.getEncryptedPassword());
        }else{
            password = cryptoService.generateRandomPassword();
            keystore = new Keystore();
            keystore.setEncryptedPassword(cryptoService.encryptAES(password));
            keystore.setUser(admin);
            keystoreRepository.save(keystore);
        }

        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectAndIssuer = buildX500NameFromDto(dto);
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        X509Certificate cert = certificateFactory.createCertificate(
                subjectAndIssuer, subjectAndIssuer,
                keyPair.getPublic(), keyPair.getPrivate(),
                dto.getValidFrom(), dto.getValidTo(),
                serialNumber, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, serialNumber.toString()
        );

        String alias = serialNumber.toString();
        var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());
        ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        return saveCertificateEntity(cert, admin, keystore, CertificateType.ROOT, serialNumber.toString());
    }

    @Transactional
    public Certificate issueCertificate(CertificateIssueDTO dto) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User subjectUser = userRepository.findByEmail(subjectEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + subjectEmail));

        // 1. Validacija izdavaoca
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber(), subjectUser);

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

        int keyUsage;
        CertificateType type;
        if(dto.isCa()){
            type = CertificateType.INTERMEDIATE;
            keyUsage = KeyUsage.keyCertSign | KeyUsage.cRLSign;
        }
        else{
            type = CertificateType.END_ENTITY;
            keyUsage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        }

        // 4. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate(
            subjectName, issuerName,
            subjectKeyPair.getPublic(), issuerPrivateKey,
            dto.getValidFrom(), dto.getValidTo(),
            serialNumber, dto.isCa(), keyUsage, issuerCertData.getSerialNumber()
        );

        if(dto.isCa()){
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

            if(subjectUser.getRole() == UserRole.ADMIN){
                subjectUser = userRepository.findByEmail(issuerCertData.getEmail())
                        .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + issuerCertData.getEmail()));
            }
        }
        else{
            String alias = serialNumber.toString();
            var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

            ks.setCertificateEntry(alias, newCert);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        }
        return saveCertificateEntity(newCert, subjectUser, keystore, type, issuerCertData.getSerialNumber());
    }

    @Transactional
    public Certificate issueE2ECertificate(Long csrId) throws Exception {
        // 1. Dobavljanje CSR-a
        Csr csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new ResourceNotFoundException("CSR zahtev nije pronađen."));

        if (csr.getStatus() != CsrStatus.PENDING) {
            throw new IllegalArgumentException("CSR zahtev nije u statusu PENDING.");
        }

        User subjectUser = csr.getUser();


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;


        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User CAUser = userRepository.findByEmail(subjectEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + subjectEmail));

        // 4. Dobavljanje Izdavaoca (CA) na osnovu podatka iz CSR-a
        Certificate issuerCertEntity = validateIssuer(csr.getIssuerSerialNumber(), CAUser); // Tvoja postojeća validacija

        // 3. Priprema Keystore-a za Subject User-a
        // Ako korisnik nema keystore, kreiramo ga. Ako ima, koristimo postojeći.
        Keystore subjectKeystore;
        String subjectKeystorePass;

        Optional<Keystore> optionalKeystore = keystoreRepository.findByUser_Id(subjectUser.getId());
        if (optionalKeystore.isPresent()) {
            subjectKeystore = optionalKeystore.get();
            subjectKeystorePass = cryptoService.decryptAES(subjectKeystore.getEncryptedPassword());
        } else {
            // Kreiranje novog keystore-a
            subjectKeystorePass = cryptoService.generateRandomPassword();
            subjectKeystore = new Keystore();
            subjectKeystore.setEncryptedPassword(cryptoService.encryptAES(subjectKeystorePass));
            subjectKeystore.setUser(subjectUser);
            keystoreRepository.save(subjectKeystore);
        }

        // 5. Učitavanje Privatnog ključa IZDAVAOCA (CA)
        Keystore issuerKeystore = issuerCertEntity.getKeystore();
        String issuerPass = cryptoService.decryptAES(issuerKeystore.getEncryptedPassword());

        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(
                issuerKeystore.getId(),
                issuerPass.toCharArray(),
                issuerCertEntity.getAlias()
        );

        // Ime izdavaoca za sertifikat
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(
                issuerKeystore.getId(), issuerPass.toCharArray(), issuerCertEntity.getAlias());
        X509Certificate issuerX509 = (X509Certificate) issuerChain[0];
        X500Name issuerName = X500Name.getInstance(issuerX509.getSubjectX500Principal().getEncoded());

        // 6. Priprema podataka za NOVI sertifikat iz CSR-a

        // a) Konverzija String Public Key -> PublicKey objekat
        PublicKey subjectPublicKey = convertStringToPublicKey(csr.getPublicKey());

        // b) Kreiranje X500Name (Subject) iz podataka u CSR-u
        X500Name subjectName = buildX500NameFromCsr(csr);

        // c) Generisanje serijskog broja
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        // d) Postavljanje datuma (Od sada do onoga što je traženo u CSR-u)
        // Napomena: ZonedDateTime konverzija zavisi od tvoje implementacije CertificateFactory
        ZonedDateTime validFrom = ZonedDateTime.now();
        ZonedDateTime validTo = csr.getExpiresAt().atZone(ZoneId.systemDefault());

        // 7. Kreiranje Sertifikata (Factory poziv)
        X509Certificate newCert = certificateFactory.createCertificate(
                subjectName,
                issuerName,
                subjectPublicKey,       // Ključ iz CSR-a
                issuerPrivateKey,       // Potpis CA
                validFrom,
                validTo,
                serialNumber,
                false,                  // isCa = false (End Entity)
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
                issuerCertEntity.getSerialNumber()
        );

        // 8. Čuvanje u Keystore KORISNIKA (Subject)
        // Čuvamo kao TrustedCertificateEntry jer nemamo privatni ključ (on je kod korisnika)
        String alias = serialNumber.toString();
        var ks = keystoreService.loadKeyStore(subjectKeystore.getId(), subjectKeystorePass.toCharArray());

        ks.setCertificateEntry(alias, newCert);

        keystoreService.saveKeyStore(ks, subjectKeystore.getId(), subjectKeystorePass.toCharArray());

        // 9. Ažuriranje statusa CSR-a
        csr.setStatus(CsrStatus.APPROVED);
        csrRepository.save(csr);

        return saveCertificateEntity(newCert, subjectUser, subjectKeystore, CertificateType.END_ENTITY, issuerCertEntity.getSerialNumber());
    }

    // Pomoćna metoda za konverziju (ako je već nemaš)
    private PublicKey convertStringToPublicKey(String publicKeyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public Certificate createCACertKeystore(CertificateIssueDTO dto, User owner) throws Exception{
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User adminUser = userRepository.findByEmail(subjectEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + subjectEmail));

        String password = cryptoService.generateRandomPassword();
        Keystore keystore = new Keystore();
        keystore.setEncryptedPassword(cryptoService.encryptAES(password));
        keystore.setUser(owner);
        keystoreRepository.save(keystore);

        // 1. Validacija izdavaoca
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber(), adminUser);

        // 2. Učitavanje ključa i lanca roditelja
        Keystore issuerKeystore = issuerCertData.getKeystore();
        String issuerPassword = cryptoService.decryptAES(issuerKeystore.getEncryptedPassword());

        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(issuerKeystore.getId(), issuerPassword.toCharArray(), issuerCertData.getAlias());
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(issuerKeystore.getId(), issuerPassword.toCharArray(), issuerCertData.getAlias());

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

        int keyUsage = KeyUsage.keyCertSign | KeyUsage.cRLSign;

        // 4. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate(
                subjectName, issuerName,
                subjectKeyPair.getPublic(), issuerPrivateKey,
                dto.getValidFrom(), dto.getValidTo(),
                serialNumber, true, keyUsage, issuerCertData.getSerialNumber()
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

        return saveCertificateEntity(newCert, owner, keystore, CertificateType.INTERMEDIATE, issuerCertData.getSerialNumber());
    }

    private Certificate validateIssuer(String issuerSerial, User owner) throws Exception {
        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerial)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer certificate not found."));

        if(!issuer.getOwner().equals(owner) && owner.getRole() != UserRole.ADMIN) {
            throw new CertificateValidationException("You are not the owner of issuer certificate");
        }
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
        X500Name x500 = new X500Name(cert.getSubjectX500Principal().getName());
        certEntity.setCommonName(getRdnValue(x500, BCStyle.CN));
        certEntity.setOrganization(getRdnValue(x500, BCStyle.O));
        certEntity.setOrganizationalUnit(getRdnValue(x500, BCStyle.OU));
        certEntity.setCountry(getRdnValue(x500, BCStyle.C));
        certEntity.setEmail(getRdnValue(x500, BCStyle.EmailAddress));      
        certEntity.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setType(type);
        certEntity.setOwner(owner);
        certEntity.setPublicKey(Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded()));
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

    private X500Name buildX500NameFromCsr(Csr csr) {
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, csr.getCommonName());
        if (csr.getOrganization() != null) nameBuilder.addRDN(BCStyle.O, csr.getOrganization());
        if (csr.getOrganizationalUnit() != null) nameBuilder.addRDN(BCStyle.OU, csr.getOrganizationalUnit());
        if (csr.getCountry() != null) nameBuilder.addRDN(BCStyle.C, csr.getCountry());
        if (csr.getEmail() != null) nameBuilder.addRDN(BCStyle.EmailAddress, csr.getEmail());
        return nameBuilder.build();
    }

    public boolean isCertificateValid(String serialNumber) {
    Certificate cert = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new ResourceNotFoundException("Certificate not found"));
    
    if (cert.isRevoked()) return false;
    if (cert.getValidTo().isBefore(LocalDateTime.now())) return false;
    
    // Ovdje bi se u realnom sistemu proveravao i ceo lanac do Root-a
    return true;
}

    public List<Certificate> getAll(User user) {
    	if (user.getRole() == UserRole.ADMIN)
    		return certificateRepository.findAll();
    	else
    		return certificateRepository.findByOwnerId(user.getId());
    }

    public Certificate getCertificateBySerialNumber(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found"));
    }

    // U CertificateService.java

    public byte[] downloadCertificateAsDER(String serialNumber) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User user = userRepository.findByEmail(subjectEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + subjectEmail));

        Certificate certEntity = getCertificateBySerialNumber(serialNumber);
        Keystore keystore = certEntity.getKeystore();
        if(!keystore.getUser().equals(user) && user.getRole() != UserRole.ADMIN){
            throw new ResourceNotFoundException("Sertifikat nije korisnikov");
        }
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());

        // Učitavamo keystore
        java.security.KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        java.security.cert.Certificate cert = null;

        if (certEntity.getType() == CertificateType.END_ENTITY) {
            // Za EE sertifikate koristimo getCertificate (jer je Trusted Entry)
            cert = ks.getCertificate(certEntity.getAlias());
        } else {
            // Za CA/Root sertifikate koristimo lanac (jer je PrivateKey Entry)
            java.security.cert.Certificate[] chain = ks.getCertificateChain(certEntity.getAlias());
            if (chain != null && chain.length > 0) {
                cert = chain[0];
            }
        }

        if (cert == null) {
            throw new ResourceNotFoundException("Certificate not found in keystore");
        }

        return cert.getEncoded();
    }
    
    public byte[] handleOcspRequest(byte[] requestBytes) throws Exception {
        OCSPReq ocspReq;
        try {
            ocspReq = new OCSPReq(requestBytes);
        } catch (IOException e) {
            return new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null).getEncoded();
        }

        Req[] requests = ocspReq.getRequestList();
        if (requests == null || requests.length == 0) {
            return new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null).getEncoded();
        }

        Extension nonceExt = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        CertificateID certId = requests[0].getCertID();

        var certOpt = certificateRepository.findBySerialNumber(certId.getSerialNumber().toString());
        if (certOpt.isEmpty()) {
            return buildOcspResponse(null, certId, nonceExt, true, false);
        }

        Certificate cert = certOpt.get();
        return buildOcspResponse(cert, certId, nonceExt, false, cert.isRevoked());
    }
    
    public byte[] buildOcspResponse(Certificate eeCert, CertificateID certID, Extension nonce, boolean isUnknown, boolean isRevoked) throws Exception {
        String issuerSerial = isUnknown ? null : eeCert.getIssuerSerialNumber();

        Certificate issuerRecord = certificateRepository.findBySerialNumber(issuerSerial)
                .orElseThrow(() -> new Exception("Issuer certificate not found"));

        String password = cryptoService.decryptAES(issuerRecord.getKeystore().getEncryptedPassword());
        PrivateKey issuerKey = keystoreService.getPrivateKey(issuerRecord.getKeystore().getId(), password.toCharArray(), issuerRecord.getAlias());
        X509Certificate issuerCert = (X509Certificate) keystoreService.getCertificate(issuerRecord.getKeystore().getId(), password.toCharArray(), issuerRecord.getAlias());

        CertificateStatus status;
        if (isUnknown) {
            status = new UnknownStatus();
        } else if (isRevoked) {
        	RevokedInfo revokedInfo = new RevokedInfo(
        		    new ASN1GeneralizedTime(eeCert.getRevocationDate().toString()),
        		    CRLReason.lookup(eeCert.getRevocationCode())
        		);
        		status = new RevokedStatus(revokedInfo);
        } else {
            status = CertificateStatus.GOOD;
        }

        Date now = new Date();
        Date nextUpdate = Date.from(Instant.now().plus(Duration.ofHours(24)));

        BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(
                new JcaX509CertificateHolder(issuerCert).getSubjectPublicKeyInfo(),
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1)
        );

        respBuilder.addResponse(certID, status, now, nextUpdate, null);

        if (nonce != null) {
            respBuilder.setResponseExtensions(new Extensions(nonce));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);
        BasicOCSPResp basicResp = respBuilder.build(
                signer,
                new X509CertificateHolder[]{ new JcaX509CertificateHolder(issuerCert) },
                now
        );

        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp).getEncoded();
    }
    
    public Csr submitCsr(CsrDTO csrDTO) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String email = jwt.getClaimAsString("email");

        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }

        if (email == null) {
            throw new IllegalStateException("Email nije pronađen u tokenu!");
        }

        // 3. Ovo je ključno: Pravimo FINALNU varijablu za korišćenje u lambdi
        final String subjectEmail = email;

        // 4. Sada koristimo 'email' (koji je final) u DB pretrazi
        User user = userRepository.findByEmail(subjectEmail)
                .orElseThrow(() -> new IllegalStateException("Korisnik ne postoji u bazi sa emailom: " + subjectEmail));

        Certificate ca = certificateRepository.findBySerialNumber(csrDTO.getIssuerSerialNumber())
                .orElseThrow(() -> new IllegalArgumentException("Intermediate CA not found"));
        
        validateIssuer(ca.getSerialNumber(), ca.getOwner());

        if (csrDTO.expiresAt.isAfter(ca.getValidTo()))
            throw new IllegalArgumentException("Requested expiration outside CA validity");

        PKCS10CertificationRequest csrObj = parse(csrDTO.csrPem);
        X500Name x500 = csrObj.getSubject();

        String cn  = getRdnValue(x500, BCStyle.CN);
        String o   = getRdnValue(x500, BCStyle.O);
        String ou  = getRdnValue(x500, BCStyle.OU);
        String c   = getRdnValue(x500, BCStyle.C);
        String e   = getRdnValue(x500, BCStyle.EmailAddress);

        String publicKeyPem = getPublicKey(csrObj);

        Csr entity = Csr.builder()
                .commonName(cn)
                .organization(o)
                .organizationalUnit(ou)
                .country(c)
                .email(e)
                .publicKey(publicKeyPem)
                .expiresAt(csrDTO.expiresAt)
                .issuerSerialNumber(csrDTO.getIssuerSerialNumber())
                .issuedAt(LocalDateTime.now())
                .status(CsrStatus.PENDING)
                .user(user)
                .build();

        return csrRepository.save(entity);
    }
	
	private String getRdnValue(X500Name x500, ASN1ObjectIdentifier type) {
        RDN[] rdns = x500.getRDNs(type);
        if (rdns != null && rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    private PKCS10CertificationRequest parse(String pem) {
        try {
            // Normalizuj sve vrste line endinga
            String normalized = pem.replace("\r\n", "\n")
                    .replace("\r", "\n")
                    .trim();

            // Izvuci samo base64 sadrzaj izmedju markera
            String base64 = normalized
                    .replaceAll("-----BEGIN[^-]+-----", "")
                    .replaceAll("-----END[^-]+-----", "")
                    .replaceAll("\\s+", ""); // ukloni sve whitespace ukljucujuci \n

            if (base64.isEmpty()) {
                throw new IllegalArgumentException("Invalid CSR PEM - no content found");
            }

            byte[] decoded = Base64.getDecoder().decode(base64);
            return new PKCS10CertificationRequest(decoded);

        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to parse CSR", e);
        }
    }

	private String getPublicKey(PKCS10CertificationRequest csr) {
	    try {
	        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
	        byte[] encoded = pkInfo.getEncoded();
	        // Just Base64 string of the key
	        return Base64.getEncoder().encodeToString(encoded);
	    } catch (IOException e) {
	        throw new IllegalArgumentException("Failed to extract public key", e);
	    }
	}
	
	public Certificate revoke(String serialNumber, int revocationCode) {
		 List<Certificate> certs = certificateRepository.findAll();
		 return recursiveRevoke(serialNumber, revocationCode, certs);
	}
	
	private Certificate recursiveRevoke(String parentSerialNumber, int revocationCode, List<Certificate> certificates) {
		Certificate certificate = certificates.stream().filter(c->c.getSerialNumber().equals(parentSerialNumber)).findFirst().orElse(null);
		certificate.setRevoked(true);
		certificate.setRevocationDate(LocalDateTime.now());
		certificate.setRevocationCode(revocationCode);
		certificateRepository.save(certificate);
		List<Certificate> childrenCerts = certificates.stream().filter(cert->cert.getIssuerSerialNumber().equals(parentSerialNumber)).toList();
		for (Certificate cert: childrenCerts) 
			recursiveRevoke(cert.getSerialNumber(), revocationCode, certificates);
		return certificate;
	}
	
	public List<Certificate> getAllCA(){
		return certificateRepository.findAllByType(CertificateType.INTERMEDIATE);
	}
	
	public List<CsrViewDTO> getAllCACsr(Long userId) {
	    return csrRepository.findCsrsBySigningCaOwner(userId).stream()
	        .map(csr -> CsrViewDTO.builder()
	        	.id(csr.getId())
	            .commonName(csr.getCommonName())
	            .organization(csr.getOrganization())
	            .organizationalUnit(csr.getOrganizationalUnit())
	            .country(csr.getCountry())
	            .email(csr.getEmail())
	            .publicKey(csr.getPublicKey())
	            .expiresAt(csr.getExpiresAt())
	            .issuedAt(csr.getIssuedAt())
	            .issuerSerialNumber(csr.getIssuerSerialNumber())
	            .status(csr.getStatus())
	            .build())
	        .collect(Collectors.toList());
	}
	
	public List<Certificate> getAllEE() {
	    return certificateRepository.findAllByType(CertificateType.END_ENTITY)
	        .stream()
	        .filter(cert ->  cert.getOwner().getRole() == UserRole.USER)
	        .collect(Collectors.toList());
	}
}