package ee.ria.ocspcrl.service.crl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlLoadingService {

    private final CrlDownloadService crlDownloadService;

    // Using "fixedDelayString" ensures that the countdown for the next execution will not be started before the
    // previous execution has been finished, so there will be no "parallel" executions.
    @Scheduled(fixedDelayString = "${ocsp-crl-fallback.crl-loading-interval:30s}")
    public void updateCrlsTask(){
        log.info("Updating CRLs...");
        crlDownloadService.downloadAllCrls();
    }
}
