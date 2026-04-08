package ee.ria.ocspcrl.scheduler;

import ee.ria.ocspcrl.CrlDownloadUtils;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CrlDownloadSchedulerTest {

    @Mock
    private CrlDownloadService crlDownloadService;

    @Mock
    private ThreadPoolTaskScheduler taskScheduler;

    private CrlConfigurationProperties properties;

    @BeforeEach
    void setup() {
        properties = CrlDownloadUtils.createConfigurationProperties();
    }

    @Test
    void scheduleTasks_noChains_schedulesNoTasks() {
        properties = properties.withCertificateChains(List.of());
        CrlDownloadScheduler scheduler = new CrlDownloadScheduler(properties, crlDownloadService, taskScheduler);

        scheduler.scheduleTasks();

        verify(taskScheduler, never()).scheduleWithFixedDelay(any(), any(Duration.class));
    }

    @Test
    void scheduleTasks_oneChain_schedulesOneTask() {
        properties = properties
                .withCertificateChains(List.of(CrlDownloadUtils.createChain()))
                .withCrlLoadingInterval(Duration.ofSeconds(30));
        CrlDownloadScheduler scheduler = new CrlDownloadScheduler(properties, crlDownloadService, taskScheduler);

        scheduler.scheduleTasks();

        verify(taskScheduler).scheduleWithFixedDelay(any(), eq(Duration.ofSeconds(30)));
    }

    @Test
    void scheduleTasks_twoChains_schedulesTaskForEachChain() {
        properties = properties
                .withCertificateChains(List.of(CrlDownloadUtils.createChain(), CrlDownloadUtils.createChain()))
                .withCrlLoadingInterval(Duration.ofSeconds(30));
        CrlDownloadScheduler scheduler = new CrlDownloadScheduler(properties, crlDownloadService, taskScheduler);

        scheduler.scheduleTasks();

        verify(taskScheduler, times(2)).scheduleWithFixedDelay(any(), eq(Duration.ofSeconds(30)));
    }

    @Test
    void scheduleTasks_scheduledTask_callsDownloadCrlWithChain() throws Exception {
        properties = properties
                .withCertificateChains(List.of(CrlDownloadUtils.createChain()))
                .withCrlLoadingInterval(Duration.ofSeconds(30));
        CrlDownloadScheduler scheduler = new CrlDownloadScheduler(properties, crlDownloadService, taskScheduler);
        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

        scheduler.scheduleTasks();
        verify(taskScheduler).scheduleWithFixedDelay(runnableCaptor.capture(), any(Duration.class));
        runnableCaptor.getValue().run();

        verify(crlDownloadService).downloadCrl(CrlDownloadUtils.createChain());
    }

    @Test
    void scheduleTasks_downloadCrlThrowsException_doesNotPropagate() throws Exception {
        properties = properties
                .withCertificateChains(List.of(CrlDownloadUtils.createChain()))
                .withCrlLoadingInterval(Duration.ofSeconds(30));
        CrlDownloadScheduler scheduler = new CrlDownloadScheduler(properties, crlDownloadService, taskScheduler);
        doThrow(new RuntimeException("Connection refused")).when(crlDownloadService).downloadCrl(any());
        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

        scheduler.scheduleTasks();
        verify(taskScheduler).scheduleWithFixedDelay(runnableCaptor.capture(), any(Duration.class));

        assertThatNoException().isThrownBy(() -> runnableCaptor.getValue().run());
    }

    @Test
    void scheduleTasks_multipleChainsScheduled_tasksRunInParallel() throws Exception {
        int chainCount = 2;
        CountDownLatch bothStarted = new CountDownLatch(chainCount);
        CountDownLatch release = new CountDownLatch(1);

        ThreadPoolTaskScheduler realScheduler = new ThreadPoolTaskScheduler();
        realScheduler.setPoolSize(chainCount);
        realScheduler.initialize();

        try {
            properties = properties
                    .withCertificateChains(List.of(CrlDownloadUtils.createChain(), CrlDownloadUtils.createChain()))
                    .withCrlLoadingInterval(Duration.ofSeconds(30));
            doAnswer(invocation -> {
                bothStarted.countDown();
                release.await();
                return null;
            }).when(crlDownloadService).downloadCrl(any());

            new CrlDownloadScheduler(properties, crlDownloadService, realScheduler).scheduleTasks();

            assertThat(bothStarted.await(5, TimeUnit.SECONDS))
                    .as("both tasks should start before either finishes")
                    .isTrue();
        } finally {
            release.countDown();
            realScheduler.shutdown();
        }
    }
}
