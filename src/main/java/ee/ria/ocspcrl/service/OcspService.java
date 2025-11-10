package ee.ria.ocspcrl.service;

import ee.ria.ocspcrl.exception.CertificateChainMismatchException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OcspService {

    private final OcspKeyService keyService;
    private final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

    @SuppressWarnings({"DataFlowIssue"})
    public OCSPResp handleRequest(OCSPReq ocspReq, X509CertificateHolder issuerCertificate) throws Exception {
        Req certRequest = null;
        byte[] nonce = null;
        try {
            validateRequestVersion(ocspReq);
            certRequest = getCertificateRequest(ocspReq);
            nonce = getNonce(ocspReq);
            validateNonce(nonce);
            validateIssuer(certRequest, issuerCertificate);
        } catch (CertificateChainMismatchException e) {
            // CertificateChainMismatchException is only thrown from validateIssuer() method, therefore
            // we can be sure that certRequest and nonce values have been already been assigned.
            return createSignedOcspResponse(certRequest.getCertID(), nonce, new UnknownStatus());
        } catch (Exception e) {
            // For request parsing exceptions, malformed request is returned with HTTP 200
            log.info("Invalid OCSP request", e);
            return createResponseForMalformedRequest();
        }
        // All the other exceptions are handled in the controller by returning HTTP 500
        return createSignedOcspResponse(certRequest.getCertID(), nonce, CertificateStatus.GOOD);
    }

    private OCSPResp createSignedOcspResponse(CertificateID certId, byte[] nonce, CertificateStatus status) throws Exception {
        X509CertificateHolder signingCertHolder = getSigningCertificateHolder();
        ResponderID responderID = new ResponderID(signingCertHolder.getSubject());
        RespID respID = new RespID(responderID);
        BasicOCSPRespBuilder signableResponseBuilder = new BasicOCSPRespBuilder(respID);
        signableResponseBuilder.setResponseExtensions(createNonceExtension(nonce));
        signableResponseBuilder.addResponse(certId, status);
        BasicOCSPResp basicResp = signBasicResponse(signingCertHolder, signableResponseBuilder);
        return wrapIntoOcspResp(basicResp);
    }

    private static void validateNonce(byte[] nonce) {
        if (nonce == null || nonce.length == 0) {
            throw new IllegalArgumentException("OCSP request nonce extension was empty");
        }
    }

    static byte[] getNonce(OCSPReq ocspReq) {
        ASN1OctetString parsedValue = (ASN1OctetString) ocspReq
                .getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)
                .getParsedValue();
        return parsedValue.getOctets();
    }

    static Extensions createNonceExtension(byte[] nonceValue) throws IOException {
        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false,
                new DEROctetString(nonceValue)
        );
        return extGenerator.generate();
    }

    private static OCSPResp createResponseForMalformedRequest() throws OCSPException {
        return new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null);
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
            throw new CertificateChainMismatchException("OCSP request `CertID` does not match expected issuer certificate");
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

    private X509CertificateHolder getSigningCertificateHolder() throws IOException, CertificateEncodingException {
        X509Certificate signingCert = keyService.getOcspSigningCert();
        return new X509CertificateHolder(signingCert.getEncoded());
    }

    private ContentSigner createContentSigner() throws OperatorCreationException {
        PrivateKey signingKey = keyService.getOcspSigningKey();
        // TODO: Extract signatureAlgorithm from key?
        return new JcaContentSignerBuilder("SHA384withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKey);
    }

    private static OCSPResp wrapIntoOcspResp(BasicOCSPResp basicResp) throws OCSPException {
        OCSPRespBuilder builder = new OCSPRespBuilder();
        return builder.build(OCSPResponseStatus.SUCCESSFUL, basicResp);
    }

    private BasicOCSPResp signBasicResponse(
            X509CertificateHolder signingCertHolder,
            BasicOCSPRespBuilder basicBuilder) throws OCSPException, OperatorCreationException {
        ContentSigner signer = createContentSigner();
        X509CertificateHolder[] certificateChain = {signingCertHolder};
        Date producedAt = new Date();
        return basicBuilder.build(
                signer,
                certificateChain,
                producedAt
        );
    }
}
