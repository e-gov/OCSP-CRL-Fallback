package ee.ria.ocspcrl.scheduler;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import org.springframework.boot.task.ThreadPoolTaskSchedulerBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@Configuration
public class CrlDownloadTaskSchedulerConfiguration {

    @Bean
    public ThreadPoolTaskScheduler crlDownloadTaskScheduler(CrlConfigurationProperties properties) {
        return new ThreadPoolTaskSchedulerBuilder()
                .threadNamePrefix("crl-download-")
                .poolSize(properties.certificateChains().size())
                .build();
    }
}
