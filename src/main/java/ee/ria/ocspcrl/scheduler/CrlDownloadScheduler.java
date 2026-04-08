package ee.ria.ocspcrl.scheduler;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class CrlDownloadScheduler {

    private final CrlConfigurationProperties properties;
    private final CrlDownloadService crlDownloadService;
    private final ThreadPoolTaskScheduler crlDownloadTaskScheduler;

    public void scheduleTasks() {
        List<CrlConfigurationProperties.CertificateChain> chains = properties.certificateChains();
        for (CrlConfigurationProperties.CertificateChain chain : chains) {
            crlDownloadTaskScheduler.scheduleWithFixedDelay(
                    () -> handleDownload(chain),
                    properties.crlLoadingInterval()
            );
        }
    }

    private void handleDownload(CrlConfigurationProperties.CertificateChain chain) {
        try {
            crlDownloadService.downloadCrl(chain);
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to download CRL for {}", chain.name());
        }
    }
}
