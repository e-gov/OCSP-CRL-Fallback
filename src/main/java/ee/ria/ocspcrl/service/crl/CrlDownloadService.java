package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CrlDownload;
import ee.ria.ocspcrl.service.FileWritingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.restclient.autoconfigure.RestClientSsl;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlDownloadService {

    private final CrlConfigurationProperties properties;
    private final RestClientSsl restClientSsl;
    private final FileWritingService fileWritingService;

    public void downloadAllCrls() {
        for (var chain : properties.certificateChains()) {
            try {
                downloadCrl(chain);
            } catch (Exception e) {
                log.atError()
                        .setCause(e)
                        .log("Failed to download CRL for {}", chain.name());
            }
        }
    }

    private void downloadCrl(CertificateChain chain) throws IOException {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory();
        CrlDownload crl = chain.crlDownload();
        requestFactory.setReadTimeout(crl.timeout());
        RestClient client = createRestClient(crl, requestFactory);
        log.info("Downloading file: {}", crl.url());
        byte[] content = downloadFile(client);
        if (content == null) {
            throw new RuntimeException("Received empty content from URL: " + crl.url());
        }
        fileWritingService.writeToFile(getTargetFilePath(chain.name()), content);
    }

    private RestClient createRestClient(CrlDownload crl, JdkClientHttpRequestFactory requestFactory) {
        URL url = crl.url();
        // Check whether to use configured truststore bundle or Java's default truststore for HTTPS connections.
        // HTTP connections ignore truststore settings.
        if (crl.tlsTruststoreBundle() != null) {
            return RestClient.builder()
                .baseUrl(url.toString())
                // TODO AUT-2429: Add timeout: we can't use `.requestFactory(requestFactory)` here as it would be
                //        immediately overwritten by `.apply(restClientSsl.fromBundle()` which internally calls
                //        `builder.requestFactory(...)`
                .apply(restClientSsl.fromBundle(crl.tlsTruststoreBundle()))
                .build();
        } else {
            return RestClient.builder()
                .baseUrl(url.toString())
                .requestFactory(requestFactory)
                .build();
        }
    }

    private Path getTargetFilePath(String chainName) {
        String targetDirPath = properties.tmpPath();
        String fileName = chainName + ".crl.tmp";
        return Path.of(targetDirPath, fileName);
    }

    private byte[] downloadFile(RestClient client) {
        return client.get()
                .retrieve()
                .body(byte[].class);
    }
}
