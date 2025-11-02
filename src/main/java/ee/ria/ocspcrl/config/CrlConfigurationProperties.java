package ee.ria.ocspcrl.config;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

@Validated
@ConfigurationProperties("ocsp-crl-fallback")
public record CrlConfigurationProperties (
    @NotNull Duration crlLoadingInterval,
    List<CertificateChain> certificateChains,
    @NotNull Path tmpPath
) {

    public List<CertificateChain> certificateChains() {
        return this.certificateChains != null ? this.certificateChains : List.of();
    }

    public Map<String, CertificateChain> certificateChainsByName() {
        return certificateChains().stream()
                .collect(toMap(CertificateChain::name, identity()));
    }

    public CertificateChain certificateChain(String name) {
        return certificateChainsByName().get(name);
    }

    public record CertificateChain(
            @Pattern(regexp = "\\w[\\w\\-.]*") String name,
            @NotNull X509CertificateHolder issuerCertificate,
            @NotNull CrlDownload crlDownload
    ) {}

    public record CrlDownload(
            @NotNull URL url,
            @NotNull Duration timeout,
            String tlsTruststoreBundle
    ) {}
}
