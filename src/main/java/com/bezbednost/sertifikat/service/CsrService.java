package com.bezbednost.sertifikat.service;

import java.io.IOException;
import java.io.StringReader;
import java.time.LocalDateTime;
import java.util.Base64;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bezbednost.sertifikat.dto.CsrDTO;
import com.bezbednost.sertifikat.model.Certificate;
import com.bezbednost.sertifikat.model.Csr;
import com.bezbednost.sertifikat.model.CsrStatus;
import com.bezbednost.sertifikat.repository.CertificateRepository;
import com.bezbednost.sertifikat.repository.CsrRepository;

@Service
public class CsrService {

	@Autowired
	private CsrRepository csrRepository;
	
	@Autowired
	private CertificateRepository certificateRepository;
	
	
	public Csr submitCsr(CsrDTO csrDTO) {

        Certificate ca = certificateRepository.findById(csrDTO.intermediateCaId)
                .orElseThrow(() -> new IllegalArgumentException("Intermediate CA not found"));

        if (ca.isRevoked()) throw new IllegalArgumentException("CA is revoked");
        if (csrDTO.expiresAt.isAfter(ca.getValidTo()))
            throw new IllegalArgumentException("Requested expiration outside CA validity");

        PKCS10CertificationRequest csrObj = parse(csrDTO.csrPem);
        X500Name x500 = csrObj.getSubject();

        // Extract X500Name fields
        String cn  = getRdnValue(x500, BCStyle.CN);
        String o   = getRdnValue(x500, BCStyle.O);
        String ou  = getRdnValue(x500, BCStyle.OU);
        String c   = getRdnValue(x500, BCStyle.C);
        String st  = getRdnValue(x500, BCStyle.ST);
        String l   = getRdnValue(x500, BCStyle.L);

        String publicKeyPem = getPublicKey(csrObj);

        Csr entity = Csr.builder()
                .commonName(cn)
                .organization(o)
                .organizationalUnit(ou)
                .country(c)
                .state(st)
                .locality(l)
                .publicKey(publicKeyPem)
                .expiresAt(csrDTO.expiresAt)
                .intermediateCaId(1L)
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

	public String getPublicKey(PKCS10CertificationRequest csr) {
	    try {
	        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
	        byte[] encoded = pkInfo.getEncoded();
	        // Just Base64 string of the key
	        return Base64.getEncoder().encodeToString(encoded);
	    } catch (IOException e) {
	        throw new IllegalArgumentException("Failed to extract public key", e);
	    }
	}
	
}
