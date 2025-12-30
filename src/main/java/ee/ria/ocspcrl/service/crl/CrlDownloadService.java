package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.CrlCache;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CrlDownload;
import ee.ria.ocspcrl.gateway.CrlGateway;
import ee.ria.ocspcrl.gateway.CrlGatewayFactory;
import ee.ria.ocspcrl.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CRLHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlDownloadService {

    private static final FileService.FileType FILE_TYPE = FileService.FileType.TEMP;

    private final CrlConfigurationProperties properties;
    private final FileService fileService;
    private final CrlGatewayFactory crlGatewayFactory;
    private final CrlValidationService crlValidationService;
    private final CrlCache crlCache;

    public void downloadAllCrls() {
        for (var chain : properties.certificateChains()) {
            try {
                downloadCrl(chain);
            } catch (Exception e) {
                log.atError()
                        .setCause(e)
                        .log("Failed to download CRL for {}", chain.name());
            }
        }
    }

    private void downloadCrl(CertificateChain chain) throws IOException {
        CrlDownload crl = chain.crlDownload();
        CrlGateway gateway = crlGatewayFactory.create(crl);
        log.info("Downloading file: {}", crl.url());

        CrlGateway.CrlResponse response = gateway.downloadFile(getRequestHeaders(chain.name()));

        if (response instanceof CrlGateway.CrlFileNotModifiedResponse) {
            log.info("CRL has no modifications: {}", chain.name());
            return;
        }

        if (!(response instanceof CrlGateway.NewCrlFileResponse newCrlFileResponse)) {
            throw new RuntimeException("Unexpected response type: " + response.getClass().getName());
        }

        if (newCrlFileResponse.crl() == null) {
            throw new RuntimeException("Received empty content from URL: " + crl.url());
        }

        fileService.serializeToFile(chain.name(), newCrlFileResponse, FILE_TYPE);
        log.info("Downloaded file: {}", crl.url());

        X509CRLHolder crlHolder = new X509CRLHolder(newCrlFileResponse.crl());
        if (!crlValidationService.isCrlValid(chain.name(), crlHolder)) {
            log.warn("Aborted downloading CRL for chain {}", chain.name());
            return;
        }

        crlCache.updateCrl(chain.name(), crlHolder);

        log.info("Moving CRL from tmp to validated directory: {}", chain.name());
        fileService.moveValidCrl(chain.name());
        log.info("Moved CRL to validated directory: {}",  chain.name());

        log.info("Moving headers from tmp to validated directory: {}", chain.name());
        fileService.moveHeaders(chain.name());
        log.info("Moved headers to validated directory: {}", chain.name());
    }

    private CrlGateway.CrlCacheKey getRequestHeaders(String chainName) {
        if (!fileService.shouldReadHeadersFromFile(chainName, FILE_TYPE)) {
            return null;
        }

        try {
            return fileService.deserializeCrlCacheKeyFromFile(chainName, FILE_TYPE);
        } catch (IOException e) {
            log.error("Could not read headers from local file for chain {}", chainName);
            return null;
        }
    }

}
