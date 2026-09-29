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
import java.util.regex.Pattern;

@Slf4j
@Component
@WebEndpoint(id = "crlreload")
@RequiredArgsConstructor
public class CrlReloadEndpoint {

    private static final Pattern CHAIN_NAME = Pattern.compile("\\w[\\w\\-.]*");

    private final CrlConfigurationProperties properties;
    private final CrlDownloadService crlDownloadService;

    @WriteOperation
    public WebEndpointResponse<Map<String, ChainReloadResult>> reload(@Nullable String chain) {
        if (chain == null) {
            return reloadResponse(properties.certificateChains());
        }

        if (!CHAIN_NAME.matcher(chain).matches()) {
            log.warn("Requested CRL reload with a malformed certificate chain name");
            return new WebEndpointResponse<>(Map.of(), WebEndpointResponse.STATUS_BAD_REQUEST);
        }

        CertificateChain certificateChain = properties.certificateChain(chain);
        if (certificateChain == null) {
            log.warn("Requested CRL reload for unknown certificate chain: {}", chain);
            return new WebEndpointResponse<>(
                    Map.of(chain, ChainReloadResult.of(CrlDownloadResult.UNKNOWN_CHAIN)),
                    WebEndpointResponse.STATUS_NOT_FOUND
            );
        }

        return reloadResponse(List.of(certificateChain));
    }

    private WebEndpointResponse<Map<String, ChainReloadResult>> reloadResponse(List<CertificateChain> chains) {
        Map<String, ChainReloadResult> results = reloadChains(chains);
        return new WebEndpointResponse<>(results, resultStatus(results));
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
            return ChainReloadResult.of(crlDownloadService.downloadCrl(chain));
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to reload CRL for {}", chain.name());
            // Type only - exception messages from the HTTP client embed the CRL distribution point
            // URI. The message and stack trace go to the log above.
            return new ChainReloadResult(CrlDownloadResult.FAILURE, e.getClass().getName());
        }
    }

    private int resultStatus(Map<String, ChainReloadResult> results) {
        if (anyResultIs(results, CrlDownloadResult.FAILURE)) {
            return WebEndpointResponse.STATUS_INTERNAL_SERVER_ERROR;
        }
        if (anyResultIs(results, CrlDownloadResult.BUSY)) {
            return HttpStatus.CONFLICT.value();
        }
        return WebEndpointResponse.STATUS_OK;
    }

    private boolean anyResultIs(Map<String, ChainReloadResult> results, CrlDownloadResult result) {
        return results.values().stream().anyMatch(chainResult -> chainResult.result() == result);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ChainReloadResult(CrlDownloadResult result, String error) {

        static ChainReloadResult of(CrlDownloadResult result) {
            return new ChainReloadResult(result, null);
        }
    }
}
