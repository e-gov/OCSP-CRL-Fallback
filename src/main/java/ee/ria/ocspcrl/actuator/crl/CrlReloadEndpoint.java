package ee.ria.ocspcrl.actuator.crl;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@WebEndpoint(id = "crlreload")
@RequiredArgsConstructor
public class CrlReloadEndpoint {

    private final CrlConfigurationProperties properties;
    private final CrlDownloadService crlDownloadService;

    @WriteOperation
    public WebEndpointResponse<Map<String, ChainReloadResult>> reload(@Nullable String chain) {
        if (chain == null) {
            return reloadResponse(properties.certificateChains());
        }

        CertificateChain certificateChain = properties.certificateChain(chain);
        if (certificateChain == null) {
            log.warn("Requested CRL reload for unknown certificate chain: {}", chain);
            return new WebEndpointResponse<>(
                    Map.of(chain, ChainReloadResult.of(ChainReloadStatus.UNKNOWN_CHAIN)),
                    HttpStatus.NOT_FOUND.value()
            );
        }

        return reloadResponse(List.of(certificateChain));
    }

    private WebEndpointResponse<Map<String, ChainReloadResult>> reloadResponse(List<CertificateChain> chains) {
        Map<String, ChainReloadResult> results = reloadChains(chains);
        return new WebEndpointResponse<>(results, resultStatus(results).value());
    }

    private Map<String, ChainReloadResult> reloadChains(List<CertificateChain> chains) {
        Map<String, ChainReloadResult> results = new LinkedHashMap<>();
        for (CertificateChain chain : chains) {
            results.put(chain.name(), reloadChain(chain));
        }
        return results;
    }

    private ChainReloadResult reloadChain(CertificateChain chain) {
        log.info("Reloading CRL on request: {}", chain.name());
        try {
            return ChainReloadResult.of(ChainReloadStatus.of(crlDownloadService.downloadCrl(chain)));
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to reload CRL for {}", chain.name());
            // Type only - exception messages from the HTTP client embed the CRL distribution point
            // URI. The message and stack trace go to the log above.
            return new ChainReloadResult(ChainReloadStatus.FAILURE, e.getClass().getName());
        }
    }

    private HttpStatus resultStatus(Map<String, ChainReloadResult> results) {
        Set<ChainReloadStatus> statuses = results.values().stream()
                .map(ChainReloadResult::result)
                .collect(Collectors.toSet());
        if (statuses.contains(ChainReloadStatus.FAILURE)) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
        if (statuses.contains(ChainReloadStatus.BUSY)) {
            return HttpStatus.CONFLICT;
        }
        return HttpStatus.OK;
    }

    public enum ChainReloadStatus {
        UPDATED,
        NOT_MODIFIED,
        REJECTED,
        BUSY,
        FAILURE,
        UNKNOWN_CHAIN;

        static ChainReloadStatus of(CrlDownloadResult result) {
            return valueOf(result.name());
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ChainReloadResult(ChainReloadStatus result, String error) {

        static ChainReloadResult of(ChainReloadStatus result) {
            return new ChainReloadResult(result, null);
        }
    }
}
