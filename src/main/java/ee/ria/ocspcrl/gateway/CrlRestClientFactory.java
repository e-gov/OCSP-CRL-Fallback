package ee.ria.ocspcrl.gateway;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.net.URL;

@Service
@RequiredArgsConstructor
public class CrlRestClientFactory {

    private final SslBundles sslBundles;
    private final RestClient.Builder restClientBuilder;
    private final ClientHttpRequestFactoryBuilder<?> clientHttpRequestFactoryBuilder;
    private final HttpClientSettings httpClientSettings;

    public RestClient create(CrlConfigurationProperties.CrlDownload crl) {
        URL url = crl.url();
        // Check whether to use configured truststore bundle or Java's default truststore for HTTPS connections.
        // HTTP connections ignore truststore settings.
        SslBundle sslBundle = crl.tlsTruststoreBundle() != null
                ? sslBundles.getBundle(crl.tlsTruststoreBundle())
                : null;

        HttpClientSettings settings = httpClientSettings
                .withSslBundle(sslBundle)
                // TODO Use this and/or connect timeout or some other approach.
                .withReadTimeout(crl.timeout());
        ClientHttpRequestFactory requestFactory = clientHttpRequestFactoryBuilder
                .build(settings);

        return restClientBuilder
                .baseUrl(url.toString())
                .requestFactory(requestFactory)
                .build();
    }
}
