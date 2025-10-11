package ee.ria.ocspcrl.logging;

import ch.qos.logback.classic.LoggerContext;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.LoggerFactory;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Deprecated // Move to eID-Common library
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // Ensure that logging attributes are set as early as
                                   // possible.
public class ServiceVersionLoggingConfigurer {

    public ServiceVersionLoggingConfigurer(BuildProperties buildProperties, GitProperties gitProperties) {
        String version = getVersion(buildProperties, gitProperties);

        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        context.putProperty("service.version", version);

        log.info("Application version: {}", version);
    }

    private String getVersion(BuildProperties buildProperties, GitProperties gitProperties) {
        String versionWithoutBuildNumber = buildProperties.getVersion();
        String buildNumber = gitProperties.get("build.number");
        if (StringUtils.isNotEmpty(buildNumber)) {
            return versionWithoutBuildNumber + "-" + buildNumber;
        }
        return versionWithoutBuildNumber;
    }

}
