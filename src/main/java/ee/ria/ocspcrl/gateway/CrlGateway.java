package ee.ria.ocspcrl.gateway;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

@RequiredArgsConstructor
public class CrlGateway {

    private final RestClient restClient;

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
