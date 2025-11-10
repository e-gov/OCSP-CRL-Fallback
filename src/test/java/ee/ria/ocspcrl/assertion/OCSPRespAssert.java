package ee.ria.ocspcrl.assertion;

import org.assertj.core.api.AbstractAssert;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;

import java.util.Arrays;
import java.util.Date;

public class OCSPRespAssert extends AbstractAssert<OCSPRespAssert, OCSPResp> {

    public OCSPRespAssert(OCSPResp actual) {
        super(actual, OCSPRespAssert.class);
    }

    public static OCSPRespAssert assertThat(OCSPResp actual) {
        return new OCSPRespAssert(actual);
    }

    public OCSPRespAssert hasResponseStatus(int expectedStatus) {
        isNotNull();
        int actualStatus = actual.getStatus();
        if (actualStatus != expectedStatus) {
            failWithMessage("Expected response status <%s> but was <%s>", expectedStatus, actualStatus);
        }
        return this;
    }

    @SuppressWarnings("DataFlowIssue")
    public OCSPRespAssert hasProducedAtWithinLastHour() {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        Date producedAt = basic.getProducedAt();

        if (producedAt == null) {
            failWithMessage("Expected producedAt timestamp, but it was null");
        }

        long now = System.currentTimeMillis();
        long producedAtTime = producedAt.getTime();
        long oneHour = 60L * 60L * 1000L;

        if (producedAtTime > now) {
            failWithMessage("Expected producedAt to be in the past, but it is in the future: <%s>", producedAt);
        }

        if (producedAtTime < now - oneHour) {
            failWithMessage("Expected producedAt <%s> to be within the last hour, but it is older than one hour", producedAt);
        }

        return this;
    }

    @SuppressWarnings("DataFlowIssue")
    public OCSPRespAssert hasResponderIdByName(String expectedId) {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        RespID respID = basic.getResponderId();
        ResponderID responderId = ResponderID.getInstance(respID.toASN1Primitive());

        X500Name actualName = responderId.getName();
        if (actualName == null) {
            failWithMessage("Expected responderId by name <%s> but OCSP response used key-hash form", expectedId);
        } else if (!actualName.equals(new X500Name(expectedId))) {
            failWithMessage("Expected responderId <%s> but was <%s>", expectedId, actualName);
        }
        return this;
    }

    @SuppressWarnings("DataFlowIssue")
    public OCSPRespAssert hasResponderIdByKeyHash(byte[] expectedKeyHash) {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        RespID respID = basic.getResponderId();
        ResponderID responderId = ResponderID.getInstance(respID.toASN1Primitive());

        byte[] keyHash = responderId.getKeyHash();
        if (keyHash == null) {
            failWithMessage("Expected responderId by key-hash, but OCSP response used name form");
        } else if (!Arrays.equals(expectedKeyHash, keyHash)) {
            failWithMessage("Expected responder key hash <%s> but was <%s>",
                    Arrays.toString(expectedKeyHash),
                    Arrays.toString(keyHash)
            );
        }
        return this;
    }

    public OCSPRespAssert hasCertificateStatusGood() {
        CertificateStatus actualStatus = getActualCertificateStatus();
        if (actualStatus != CertificateStatus.GOOD) {
            failWithMessage("Expected certStatus GOOD (null) but was <%s>", actualStatus);
        }
        return this;
    }

    public OCSPRespAssert hasCertificateStatusRevoked() {
        return hasCertStatusInstanceOf(RevokedStatus.class);
    }

    public OCSPRespAssert hasCertificateStatusUnknown() {
        return hasCertStatusInstanceOf(UnknownStatus.class);
    }

    @SuppressWarnings("DataFlowIssue")
    public OCSPRespAssert hasSigningCertificateSubject(String expectedDn) {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        X509CertificateHolder[] certs = basic.getCerts();
        if (certs == null || certs.length == 0) {
            failWithMessage("Expected signing certificate, but OCSP response contained no certificates");
        }
        String actualDn = certs[0].getSubject().toString();
        if (!actualDn.equals(expectedDn)) {
            failWithMessage("Expected signing certificate subject <%s> but was <%s>", expectedDn, actualDn);
        }
        return this;
    }

    @SuppressWarnings("DataFlowIssue")
    public OCSPRespAssert hasNonce(byte[] expectedNonce) {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        Extension nonceExt = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        if (expectedNonce == null) {
            if (nonceExt != null) {
                failWithMessage("Expected no nonce extension but found one");
            }
            return this;
        }

        if (nonceExt == null) {
            failWithMessage("Expected nonce extension but none found");
        }

        ASN1OctetString actualNonce = (ASN1OctetString) nonceExt.getParsedValue();
        if (!Arrays.equals(expectedNonce, actualNonce.getOctets())) {
            failWithMessage("Expected nonce <%s> but was <%s>",
                    Arrays.toString(expectedNonce),
                    Arrays.toString(actualNonce.getOctets()));
        }
        return this;
    }

    public OCSPRespAssert hasNoResponseObject() {
        Object responseObject = null;
        try {
            responseObject = actual.getResponseObject();
        } catch (OCSPException e) {
            failWithMessage("Failed to parse OCSPResp: %s", e.getMessage());
        }
        if (responseObject != null) {
            failWithMessage("Response object was not null but <%s>", responseObject);
        }
        return this;
    }

    @SuppressWarnings("DataFlowIssue")
    private CertificateStatus getActualCertificateStatus() {
        isNotNull();
        BasicOCSPResp basic = getBasicResponse();
        SingleResp[] responses = basic.getResponses();
        if (responses.length != 1) {
            failWithMessage("Expected <1> SingleResp, but found <%s>", responses.length);
        }
        return responses[0].getCertStatus();
    }

    @SuppressWarnings("DataFlowIssue")
    private BasicOCSPResp getBasicResponse() {
        try {
            Object responseObject = actual.getResponseObject();
            if (!(responseObject instanceof BasicOCSPResp)) {
                failWithMessage("Response object was not BasicOCSPResp but <%s>", responseObject);
            }
            return (BasicOCSPResp) responseObject;
        } catch (Exception e) {
            failWithMessage("Failed to parse OCSPResp: %s", e.getMessage());
            return null; // Unreachable code, but required for the compiler
        }
    }

    private OCSPRespAssert hasCertStatusInstanceOf(Class<? extends CertificateStatus> clazz) {
        CertificateStatus actualStatus = getActualCertificateStatus();
        if (actualStatus == null && clazz != null) {
            failWithMessage("Expected certStatus instance of <%s> but was GOOD (null)", clazz.getSimpleName());
        } else if (actualStatus != null && !clazz.isInstance(actualStatus)) {
            failWithMessage("Expected certStatus instance of <%s> but was <%s>",
                    clazz.getSimpleName(),
                    actualStatus.getClass().getSimpleName());
        }
        return this;
    }
}
