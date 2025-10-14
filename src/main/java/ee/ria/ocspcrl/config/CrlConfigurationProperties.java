package ee.ria.ocspcrl.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URL;
import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties("ocsp-crl-fallback")
public record CrlConfigurationProperties (
    @NotNull Duration crlLoadingInterval,
    List<CertificateChain> certificateChains,
    @NotBlank String tmpPath
) {
    public record CertificateChain(
            @Pattern(regexp = "\\w[\\w\\-.]*") String name,
            @NotNull CrlDownload crlDownload
    ) {}

    public record CrlDownload(
            @NotNull URL url,
            @NotNull Duration timeout,
            String tlsTruststoreBundle
    ) {}
}
