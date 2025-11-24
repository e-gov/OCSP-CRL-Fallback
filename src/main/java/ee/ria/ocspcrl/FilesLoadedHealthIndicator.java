package ee.ria.ocspcrl;

import lombok.Getter;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.concurrent.CountDownLatch;

@Component
public class FilesLoadedHealthIndicator implements HealthIndicator {

    private final CountDownLatch latch = new CountDownLatch(1);

    @Getter
    private boolean isReady;

    @Override
    public @Nullable Health health() {

        return isReady
                ? Health.up().build()
                : Health.outOfService().build();
    }

    public void setReady() {
        isReady = true;
        latch.countDown();
    }

    public void awaitReady() throws InterruptedException {
        latch.await();
    }
}
