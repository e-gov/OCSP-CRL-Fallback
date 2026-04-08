package ee.ria.ocspcrl;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

@UtilityClass
public class CrlDownloadUtils {

    public final String TEST_CHAIN_NAME = "test_esteid1111";
    public final String CRL_BUNDLE_NAME = "test_esteid1111-tls";
    public final Path TMP_DIR_PATH = Path.of("/tmp/path");
    public final Path CRL_DIR_PATH = Path.of("/crl/path");
    public final String CRL_PATH = "http://test.com/chain1.crl";

    public CrlConfigurationProperties createConfigurationProperties() {
        return new CrlConfigurationProperties(Duration.ofSeconds(30), List.of(createChain()), TMP_DIR_PATH, CRL_DIR_PATH);
    }

    public CrlConfigurationProperties.CertificateChain createChain() {
        CrlConfigurationProperties.CrlDownload crlDownload = createCrlDownload();
        return new CrlConfigurationProperties.CertificateChain(TEST_CHAIN_NAME, null, crlDownload);
    }

    @SneakyThrows
    public CrlConfigurationProperties.CrlDownload createCrlDownload() {
        return new CrlConfigurationProperties.CrlDownload(new URL(CRL_PATH), Duration.ofSeconds(5), CRL_BUNDLE_NAME);
    }
}
