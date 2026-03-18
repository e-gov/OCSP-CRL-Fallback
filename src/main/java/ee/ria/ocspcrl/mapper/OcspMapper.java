package ee.ria.ocspcrl.mapper;

import ee.ria.ocspcrl.logging.OcspLogger;
import ee.ria.ocspcrl.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.springframework.stereotype.Component;

import java.util.Date;

@Slf4j
@Component
public class OcspMapper {

    public OcspLogger.OcspResponseContext toOcspContext(X509CertificateHolder issuerCertificate,
                                                        CertificateID certificateId,
                                                        X509CRLHolder crlHolder,
                                                        CertificateStatus certificateStatus,
                                                        OCSPResp ocspResp) {
        return OcspLogger.OcspResponseContext.builder()
                .issuerCn(X509Utils.getSubjectCN(issuerCertificate))
                .serialNumber(certificateId.getSerialNumber().toString(16))
                .certStatus(getCertificateStatusName(certificateStatus).toString())
                .producedAt(getProducedAt(ocspResp))
                .thisUpdate(crlHolder.getThisUpdate())
                .nextUpdate(crlHolder.getNextUpdate())
                .crlNumber(X509Utils.getCrlNumber(crlHolder))
                .build();
    }

    private static CertificateStatusName getCertificateStatusName(CertificateStatus certificateStatus) {
        if (certificateStatus == null) {
            return CertificateStatusName.GOOD;
        }
        if (certificateStatus instanceof RevokedStatus) {
            return CertificateStatusName.REVOKED;
        }
        if (certificateStatus instanceof UnknownStatus) {
            return CertificateStatusName.UNKNOWN;
        }
        throw new IllegalArgumentException("Unexpected certificate status " + certificateStatus);
    }

    private static Date getProducedAt(OCSPResp ocspResp) {
        BasicOCSPResp basicResponse = null;
        try {
            basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        } catch (OCSPException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to decode OCSP response");
        }
        if (basicResponse == null) {
            return null;
        }
        return basicResponse.getProducedAt();
    }

    public enum CertificateStatusName {
        GOOD,
        REVOKED,
        UNKNOWN
    }
}
