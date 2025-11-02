package ee.ria.ocspcrl.service;

import lombok.NonNull;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OcspService {

    private final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

    public OCSPResp handleRequest(@NonNull OCSPReq ocspReq, @NonNull X509CertificateHolder issuerCertificate) {
        validateRequestVersion(ocspReq);
        Req certRequest = getCertificateRequest(ocspReq);
        validateIssuer(certRequest, issuerCertificate);
        return null;
    }

    private static void validateRequestVersion(OCSPReq ocspReq) {
        int ocspReqVersionNumber = ocspReq.getVersionNumber();
        if (ocspReqVersionNumber != 1) {
            throw new IllegalArgumentException("OCSP request version was " + ocspReqVersionNumber + ", must be 1");
        }
    }

    private static Req getCertificateRequest(OCSPReq ocspReq) {
        List<Req> requestList = List.of(ocspReq.getRequestList());
        if (requestList.isEmpty()) {
            throw new IllegalArgumentException("OCSP request `requestList` was empty");
        }
        int requestListSize = requestList.size();
        if (requestListSize > 1) {
            throw new IllegalArgumentException(
                    "OCSP request `requestList` contained " + requestListSize + " items, only 1 is supported");
        }
        return requestList.get(0);
    }

    private void validateIssuer(Req certRequest, X509CertificateHolder issuerCertificate) {
        // If support for other algorithms is "free", does it make sense to limit it?
        validateHashAlgorithm(certRequest);
        if (!matchesIssuer(certRequest, issuerCertificate)) {
            throw new IllegalArgumentException("OCSP request `CertID` does not match expected issuer certificate");
        }
    }

    private static void validateHashAlgorithm(Req certRequest) {
        ASN1ObjectIdentifier hashAlgOid = certRequest.getCertID().getHashAlgOID();
        if (!OIWObjectIdentifiers.idSHA1.equals(hashAlgOid)) {
            throw new IllegalArgumentException(
                    "OCSP request `CertID` `hashAlgorithm was \"" + hashAlgOid.getId() + "\", " +
                            "only SHA-1 (\"" + OIWObjectIdentifiers.idSHA1.getId() + "\") is supported");
        }
    }

    private boolean matchesIssuer(Req certRequest, X509CertificateHolder issuerCertificate) {
        try {
            return certRequest.getCertID().matchesIssuer(issuerCertificate, digestCalculatorProvider);
        } catch (OCSPException e) {
            throw new RuntimeException("Error validating OCSP request `CertID`", e);
        }
    }

}
