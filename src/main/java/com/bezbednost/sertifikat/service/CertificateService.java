package com.bezbednost.sertifikat.service;

import com.bezbednost.sertifikat.dto.CertificateIssueDTO;
import com.bezbednost.sertifikat.dto.CsrDTO;
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
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;

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
        serialNumber, isCa, keyUsage, issuerCertData.getSerialNumber()
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

        Certificate ca = certificateRepository.findBySerialNumber(csrDTO.getIssuerSerialNumber())
                .orElseThrow(() -> new IllegalArgumentException("Intermediate CA not found"));
        
        validateIssuer(ca.getSerialNumber());

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
        try (PemReader reader = new PemReader(new StringReader(pem.trim()))) {
            PemObject obj = reader.readPemObject();
            if (obj == null || (!obj.getType().equals("CERTIFICATE REQUEST")
                    && !obj.getType().equals("NEW CERTIFICATE REQUEST"))) {
                throw new IllegalArgumentException("Invalid CSR PEM");
            }
            return new PKCS10CertificationRequest(obj.getContent());
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
		return certificateRepository.findAllCA();
	}
	
	public List<Csr> getAllCACsr(Long userId){
		return certificateRepository.findCsrsBySigningCaOwner(userId);
	}
}