package ee.ria.ocspcrl.actuator.crl;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@Endpoint(id = "crlreload")
@RequiredArgsConstructor
public class CrlReloadEndpoint {

    static final String RESULT_UNKNOWN_CHAIN = "UNKNOWN_CHAIN";
    static final String RESULT_FAILED_PREFIX = "FAILED: ";

    private final CrlConfigurationProperties properties;
    private final CrlDownloadService crlDownloadService;

    @WriteOperation
    public WebEndpointResponse<Map<String, String>> reload(@Nullable String chain) {
        if (chain == null) {
            return reloadResponse(properties.certificateChains());
        }

        CertificateChain certificateChain = properties.certificateChain(chain);
        if (certificateChain == null) {
            log.warn("Requested CRL reload for unknown certificate chain: {}", chain);
            return new WebEndpointResponse<>(
                    Map.of(chain, RESULT_UNKNOWN_CHAIN),
                    WebEndpointResponse.STATUS_NOT_FOUND
            );
        }

        return reloadResponse(List.of(certificateChain));
    }

    private WebEndpointResponse<Map<String, String>> reloadResponse(List<CertificateChain> chains) {
        Map<String, String> results = reloadChains(chains);
        return new WebEndpointResponse<>(results, resultStatus(results));
    }

    private Map<String, String> reloadChains(List<CertificateChain> chains) {
        Map<String, String> results = new LinkedHashMap<>();
        for (CertificateChain chain : chains) {
            results.put(chain.name(), reloadChain(chain));
        }
        return results;
    }

    private String reloadChain(CertificateChain chain) {
        log.info("Reloading CRL on request: {}", chain.name());
        try {
            return crlDownloadService.downloadCrl(chain).name();
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to reload CRL for {}", chain.name());
            return failureResult(e);
        }
    }

    private String failureResult(Exception e) {
        String message = e.getMessage();
        return RESULT_FAILED_PREFIX + (message != null ? message : e.getClass().getSimpleName());
    }

    private int resultStatus(Map<String, String> results) {
        boolean anyFailed = results.values().stream().anyMatch(result -> result.startsWith(RESULT_FAILED_PREFIX));
        return anyFailed ? WebEndpointResponse.STATUS_INTERNAL_SERVER_ERROR : WebEndpointResponse.STATUS_OK;
    }
}
