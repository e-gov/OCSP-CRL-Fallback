package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.CrlCache;
import ee.ria.ocspcrl.FilesLoadedHealthIndicator;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.gateway.CrlGateway;
import ee.ria.ocspcrl.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CRLHolder;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.NoSuchFileException;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlLoadingService {

    private final CrlDownloadService crlDownloadService;
    private final FilesLoadedHealthIndicator filesLoadedHealthIndicator;
    private final CrlCache crlCache;
    private final CrlConfigurationProperties properties;
    private final FileService fileService;
    private final CrlValidationService crlValidationService;

    // Using "fixedDelayString" ensures that the countdown for the next execution will not be started before the
    // previous execution has been finished, so there will be no "parallel" executions.
    @Scheduled(fixedDelayString = "${ocsp-crl-fallback.crl-loading-interval:30s}")
    public void updateCrlsTask() throws InterruptedException {
        filesLoadedHealthIndicator.awaitReady();
        log.info("Updating CRLs...");
        crlDownloadService.downloadAllCrls();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void loadCrlsFromDisk() {
        log.info("Loading CRLs from disk...");
        for (var chain : properties.certificateChains()) {
            try {
                CrlCache.CrlInfo crlInfo = loadCrlInfoFromDisk(chain.name());
                if (crlInfo == null) {
                    continue;
                }
                if (crlInfo.getCrlHolder() == null || crlInfo.getCrlHeaders() == null) {
                    // TODO AUT-2380 Add logging
                    continue;
                }

                crlCache.updateCrlAndHeaders(chain.name(), crlInfo.getCrlHolder(), crlInfo.getCrlHeaders());
                log.info("Loaded CRL for {}", chain.name());
            } catch (Exception e) {
                log.atError()
                        .setCause(e)
                        .log("Failed to load CRL for {}", chain.name());
            }
        }
        log.info("Loading CRLs from disk completed");

        filesLoadedHealthIndicator.setReady();
    }

    private CrlCache.CrlInfo loadCrlInfoFromDisk(String chainName) throws IOException {
        X509CRLHolder crlHolder;
        CrlGateway.CrlHeaders crlHeaders;
        try {
            crlHolder = fileService.deserializeCrlFromFile(chainName, FileService.FileType.VALIDATED);
            crlHeaders = fileService.deserializeCrlHeadersFromFile(chainName, FileService.FileType.VALIDATED);
        } catch (NoSuchFileException e) {
            log.info("Cannot find file {}", e.getMessage());
            return null;
        }

        if (!crlValidationService.isCrlValid(chainName, crlHolder)) {
            log.warn("Aborted loading CRL from disk for chain {}", chainName);
            return null;
        }

        return new CrlCache.CrlInfo(crlHeaders, crlHolder);
    }
}
