package ee.ria.ocspcrl.gateway;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

public record CrlGateway(RestClient restClient) {

    @SuppressWarnings("NullableProblems")
    public CrlResponse downloadFile(@Nullable CrlHeaders crlHeaders) {
        RestClient.RequestHeadersSpec<?> headersSpec = getHeadersSpec(crlHeaders);

        ResponseEntity<byte[]> response = headersSpec
                .retrieve()
                .toEntity(byte[].class);

        HttpStatusCode statusCode = response.getStatusCode();

        if (statusCode == HttpStatus.NOT_MODIFIED) {
            return new CrlFileNotModifiedResponse(crlHeaders);
        }

        return new NewCrlFileResponse(
                response.getBody(),
                new CrlHeaders(
                        // TODO AUT-2380 Log a warning if the same header is returned multiple times
                        response.getHeaders().getFirst(HttpHeaders.LAST_MODIFIED),
                        response.getHeaders().getFirst(HttpHeaders.ETAG)
                )
        );
    }

    private RestClient.RequestHeadersSpec<?> getHeadersSpec(CrlHeaders crlHeaders) {
        RestClient.RequestHeadersSpec<?> headersSpec = restClient.get();
        if (crlHeaders == null)
            return headersSpec;

        if (crlHeaders.lastModified() != null) {
            headersSpec.header(HttpHeaders.IF_MODIFIED_SINCE, crlHeaders.lastModified());
        }
        if (crlHeaders.eTag() != null) {
            headersSpec.header(HttpHeaders.IF_NONE_MATCH, crlHeaders.eTag());
        }

        return headersSpec;
    }

    public record CrlHeaders(
            String lastModified,
            String eTag
    ) {}

    public interface CrlResponse {}

    public record NewCrlFileResponse(
            byte[] crl,
            CrlHeaders crlHeaders
    ) implements CrlResponse {}

    public record CrlFileNotModifiedResponse(
            CrlHeaders crlHeaders
    ) implements CrlResponse {}
}
