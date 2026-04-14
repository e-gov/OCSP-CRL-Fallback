package ee.ria.ocspcrl.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.ocspcrl.mapper.OcspMapper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.Date;

import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
@RequiredArgsConstructor
public class OcspLogger {

    private final OcspMapper ocspMapper;

    public void logSuccessfulResponse(X509CertificateHolder issuerCertificate,
                                      CertificateID certificateId,
                                      X509CRLHolder crlHolder,
                                      CertificateStatus certificateStatus,
                                      OCSPResp ocspResp) {
        OcspResponseContext ocspResponseContext = ocspMapper.toOcspContext(issuerCertificate, certificateId,
                crlHolder, certificateStatus, ocspResp);
        log.info(appendFields(ocspResponseContext), "Successful OCSP response");
    }

    @Builder
    public record OcspResponseContext(
        @JsonProperty("custom.issuer_cn") String issuerCn,
        @JsonProperty("custom.cert_serial_number") String serialNumber,
        @JsonProperty("custom.cert_status") String certStatus,
        @JsonProperty("custom.produced_at") Date producedAt,
        @JsonProperty("custom.this_update") Date thisUpdate,
        @JsonProperty("custom.next_update") Date nextUpdate,
        @JsonProperty("custom.crl_number") BigInteger crlNumber
    ) {}

}
