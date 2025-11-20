package ee.ria.ocspcrl.service;

import ee.ria.ocspcrl.exception.CertificateChainMismatchException;
import ee.ria.ocspcrl.exception.CertificateRevokedException;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
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
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OcspService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final OcspKeyService keyService;
    private final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

    @SuppressWarnings({"DataFlowIssue"})
    public OCSPResp handleRequest(OCSPReq ocspReq, X509CertificateHolder issuerCertificate, String chainName) throws Exception {
        Req certRequest;
        byte[] nonce;

        try {
            validateRequestVersion(ocspReq);
            certRequest = getCertificateRequest(ocspReq);
            nonce = getNonce(ocspReq);
            validateNonce(nonce);
        } catch (Exception e) {
            // For request parsing exceptions, malformed request is returned with HTTP 200
            log.info("Invalid OCSP request", e);
            return createResponseForMalformedRequest();
        }

        X509CRLHolder crlHolder = getCrlHolder(chainName);;
        if (crlHolder == null) {
            return createSignedOcspResponse(certRequest.getCertID(), nonce, null, OCSPResponseStatus.TRY_LATER, null);
        }

        try {
            validateIssuer(certRequest, issuerCertificate);
        } catch (CertificateChainMismatchException e) {
            return createSignedOcspResponse(certRequest.getCertID(), nonce, new UnknownStatus(), OCSPResponseStatus.SUCCESSFUL, crlHolder);
        } catch (Exception e) {
            // For request parsing exceptions, malformed request is returned with HTTP 200
            log.info("Invalid OCSP request", e);
            return createResponseForMalformedRequest();
        }

        try {
            ensureCertificateNotInCrl(certRequest.getCertID(), crlHolder);
        } catch (CertificateRevokedException e) {
            RevokedStatus revokedStatus = getRevokedStatus(e);
            return createSignedOcspResponse(certRequest.getCertID(), nonce, revokedStatus, OCSPResponseStatus.SUCCESSFUL, crlHolder);
        }

        // All the other exceptions are handled in the controller by returning HTTP 500
        return createSignedOcspResponse(certRequest.getCertID(), nonce, CertificateStatus.GOOD, OCSPResponseStatus.SUCCESSFUL, crlHolder);
    }

    private OCSPResp createSignedOcspResponse(CertificateID certId, byte[] nonce, CertificateStatus certificateStatus, int ocspResponseStatus, X509CRLHolder crlHolder) throws Exception {
        X509CertificateHolder signingCertHolder = getSigningCertificateHolder();
        ResponderID responderID = new ResponderID(signingCertHolder.getSubject());
        RespID respID = new RespID(responderID);
        BasicOCSPRespBuilder signableResponseBuilder = new BasicOCSPRespBuilder(respID);
        signableResponseBuilder.setResponseExtensions(createNonceExtension(nonce));
        addRevocationInformation(signableResponseBuilder, certId, certificateStatus, crlHolder);
        BasicOCSPResp basicResp = signBasicResponse(signingCertHolder, signableResponseBuilder);
        return wrapIntoOcspResp(basicResp, ocspResponseStatus);
    }

    private void addRevocationInformation(BasicOCSPRespBuilder signableResponseBuilder, CertificateID certId,
                                          CertificateStatus certificateStatus, X509CRLHolder crlHolder) {
        if (crlHolder == null) {
            signableResponseBuilder.addResponse(certId, certificateStatus);
        } else {
            Date thisUpdate = crlHolder.getThisUpdate();
            Date nextUpdate = crlHolder.getNextUpdate();
            signableResponseBuilder.addResponse(certId, certificateStatus, thisUpdate, nextUpdate);
        }
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

    private static OCSPResp wrapIntoOcspResp(BasicOCSPResp basicResp, int ocspResponseStatus) throws OCSPException {
        OCSPRespBuilder builder = new OCSPRespBuilder();
        return builder.build(ocspResponseStatus, basicResp);
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

    private X509CRLHolder getCrlHolder(String chainName) {
        // TODO AUT-2455 Replace with an actual method (from CrlCache?)
        return getPreviousCrl(chainName);
    }

    @SneakyThrows(IOException.class)
    private X509CRLHolder getPreviousCrl(String chainName) {
        Path previousValidatedCrlPath = Path.of("/var/cache/ocspcrl/crl/" + chainName + ".crl");

        if (Files.notExists(previousValidatedCrlPath)) {
            return null;
        }

        byte[] previousCrlBytes = Files.readAllBytes(previousValidatedCrlPath);
        return new X509CRLHolder(previousCrlBytes);
    }

    private void ensureCertificateNotInCrl(CertificateID certId, @NotNull X509CRLHolder crlHolder) {
        BigInteger serialNumber = certId.getSerialNumber();

        X509CRLEntryHolder revokedCertificate = crlHolder.getRevokedCertificate(serialNumber);

        if (revokedCertificate == null) {
            return;
        }

        Date revocationTime = revokedCertificate.getRevocationDate();
        Extension reasonCodeExtension = revokedCertificate.getExtension(Extension.reasonCode);
        ASN1Encodable asnReasonCode = reasonCodeExtension.getParsedValue();
        Integer revocationReason = null;
        if (asnReasonCode instanceof ASN1Enumerated enumerated) {
            revocationReason = enumerated.intValueExact();
        }
        throw new CertificateRevokedException(revocationTime, revocationReason);
    }

    private RevokedStatus getRevokedStatus(CertificateRevokedException e) {
        if (e.getRevocationReason() == null) {
            return new RevokedStatus(e.getRevocationTime());
        }
        return new RevokedStatus(e.getRevocationTime(), e.getRevocationReason());
    }
}
