package ee.ria.ocspcrl.controller.ocsp;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.service.OcspService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static ee.ria.ocspcrl.config.oscp.OcspReqHttpMessageConverter.OCSP_REQUEST_CONTENT_TYPE;
import static ee.ria.ocspcrl.config.oscp.OcspRespHttpMessageConverter.OCSP_RESPONSE_CONTENT_TYPE;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;

@RequiredArgsConstructor
@RestController
@Slf4j
public class OcspController {

    private final OcspService ocspService;
    private final CrlConfigurationProperties crlConfigurationProperties;

    @PostMapping(path = "/ocsp/{chainId}", consumes = OCSP_REQUEST_CONTENT_TYPE, produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<?> handleOcspRequest(@PathVariable String chainId, @RequestBody OCSPReq ocspReq) {
        CertificateChain certificateChain = crlConfigurationProperties.certificateChain(chainId);
        if (certificateChain == null) {
            log.info("Certificate chain \"{}\" not configured", chainId);
            return ResponseEntity.status(NOT_FOUND).build();
        }
        try {
            OCSPResp result = ocspService.handleRequest(ocspReq,
                    certificateChain.issuerCertificate(), certificateChain.name());
            return new ResponseEntity<>(result.getEncoded(), OK);
        } catch (Exception e) {
            log.error("Error handling OCSP request", e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
    }

}
