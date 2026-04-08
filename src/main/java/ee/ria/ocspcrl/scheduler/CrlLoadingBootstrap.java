package ee.ria.ocspcrl.scheduler;

import ee.ria.ocspcrl.service.crl.CrlLoadingService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CrlLoadingBootstrap {

    private final CrlLoadingService crlLoadingService;
    private final CrlDownloadScheduler crlDownloadScheduler;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        crlLoadingService.loadCrlsFromDisk();
        crlDownloadScheduler.scheduleTasks();
    }
}
