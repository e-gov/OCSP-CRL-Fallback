package ee.ria.ocspcrl.gateway;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.restclient.autoconfigure.RestClientSsl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.URL;

public class CrlGateway {

    private final RestClient restClient;
    private final RestClientSsl restClientSsl;

    public CrlGateway(CrlConfigurationProperties.CrlDownload crlDownload, RestClientSsl restClientSsl) {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory();
        requestFactory.setReadTimeout(crlDownload.timeout());
        this.restClientSsl = restClientSsl;
        this.restClient = createRestClient(crlDownload, requestFactory);
    }

    @SuppressWarnings("NullableProblems")
    public CrlResponse downloadFile(@Nullable CrlCacheKey crlCacheKey) {
        RestClient.RequestHeadersSpec<?> headersSpec = getHeadersSpec(crlCacheKey);

        ResponseEntity<byte[]> response = headersSpec
                .retrieve()
                .toEntity(byte[].class);

        HttpStatusCode statusCode = response.getStatusCode();

        if (statusCode == HttpStatus.NOT_MODIFIED) {
            return new CrlFileNotModifiedResponse(crlCacheKey);
        }

        return new NewCrlFileResponse(
                response.getBody(),
                new CrlCacheKey(
                        // TODO AUT-2380 Log a warning if the same header is returned multiple times
                        response.getHeaders().getFirst(HttpHeaders.LAST_MODIFIED),
                        response.getHeaders().getFirst(HttpHeaders.ETAG)
                )
        );
    }

    private RestClient.RequestHeadersSpec<?> getHeadersSpec(CrlCacheKey crlCacheKey) {
        RestClient.RequestHeadersSpec<?> headersSpec = restClient.get();
        if (crlCacheKey == null)
            return headersSpec;

        if (crlCacheKey.lastModified() != null) {
            headersSpec.header(HttpHeaders.IF_MODIFIED_SINCE, crlCacheKey.lastModified());
        }
        if (crlCacheKey.eTag() != null) {
            headersSpec.header(HttpHeaders.IF_NONE_MATCH, crlCacheKey.eTag());
        }

        return headersSpec;
    }

    private RestClient createRestClient(CrlConfigurationProperties.CrlDownload crl,
                                        JdkClientHttpRequestFactory requestFactory) {
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

    // TODO Reconsider the name as there is now a class called CrlCache.
    public record CrlCacheKey(
            String lastModified,
            String eTag
    ) {}

    public interface CrlResponse {}

    public record NewCrlFileResponse(
            byte[] crl,
            CrlCacheKey crlCacheKey
    ) implements CrlResponse {}

    public record CrlFileNotModifiedResponse(
            CrlCacheKey crlCacheKey
    ) implements CrlResponse {}
}
