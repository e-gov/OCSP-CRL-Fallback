package ee.ria.ocspcrl.actuator.crl;

import ee.ria.ocspcrl.CrlDownloadUtils;
import ee.ria.ocspcrl.actuator.crl.CrlReloadEndpoint.ChainReloadResult;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.BUSY;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.FAILURE;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.NOT_MODIFIED;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.REJECTED;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.UNKNOWN_CHAIN;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.UPDATED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CrlReloadEndpointTest {

    private static final String FIRST_CHAIN = "test_esteid1111";
    private static final String SECOND_CHAIN = "test_esteid2222";

    @Mock
    private CrlDownloadService crlDownloadService;

    private CrlConfigurationProperties properties;

    @BeforeEach
    void setup() {
        properties = CrlDownloadUtils.createConfigurationProperties()
                .withCertificateChains(List.of(chain(FIRST_CHAIN), chain(SECOND_CHAIN)));
    }

    @Test
    void reload_noChainGiven_downloadsEveryConfiguredChain() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(UPDATED);
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(null);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_OK);
        assertThat(response.getBody()).containsExactly(
                Map.entry(FIRST_CHAIN, result(UPDATED)),
                Map.entry(SECOND_CHAIN, result(UPDATED))
        );
        assertThat(downloadedChainNames()).containsExactly(FIRST_CHAIN, SECOND_CHAIN);
    }

    @Test
    void reload_chainGiven_downloadsOnlyThatChain() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(UPDATED);
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(SECOND_CHAIN);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_OK);
        assertThat(response.getBody()).containsExactly(Map.entry(SECOND_CHAIN, result(UPDATED)));
        assertThat(downloadedChainNames()).containsExactly(SECOND_CHAIN);
    }

    @Test
    void reload_crlNotModified_reportsNotModified() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(NOT_MODIFIED);
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(FIRST_CHAIN);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_OK);
        assertThat(response.getBody()).containsExactly(Map.entry(FIRST_CHAIN, result(NOT_MODIFIED)));
    }

    @Test
    void reload_crlRejectedByValidation_reportsRejected() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(REJECTED);
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(FIRST_CHAIN);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_OK);
        assertThat(response.getBody()).containsExactly(Map.entry(FIRST_CHAIN, result(REJECTED)));
    }

    @Test
    void reload_downloadAlreadyInProgress_reportsBusy() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(BUSY);
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(FIRST_CHAIN);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
        assertThat(response.getBody()).containsExactly(Map.entry(FIRST_CHAIN, result(BUSY)));
    }

    @Test
    void reload_oneChainFailsAndAnotherIsBusy_failureDeterminesStatus() throws Exception {
        doAnswer(invocation -> {
            CertificateChain chain = invocation.getArgument(0);
            if (FIRST_CHAIN.equals(chain.name())) {
                throw new IOException("Connection refused");
            }
            return BUSY;
        }).when(crlDownloadService).downloadCrl(any());
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(null);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).containsExactly(
                Map.entry(FIRST_CHAIN, new ChainReloadResult(FAILURE, "java.io.IOException")),
                Map.entry(SECOND_CHAIN, result(BUSY))
        );
    }

    @Test
    void reload_unknownChain_returnsNotFoundAndDownloadsNothing() throws Exception {
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload("no_such_chain");

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_NOT_FOUND);
        assertThat(response.getBody()).containsExactly(Map.entry("no_such_chain", result(UNKNOWN_CHAIN)));
        verify(crlDownloadService, never()).downloadCrl(any());
    }

    @Test
    void reload_noChainsConfigured_returnsEmptyResult() throws Exception {
        properties = properties.withCertificateChains(List.of());
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(null);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_OK);
        assertThat(response.getBody()).isEmpty();
        verify(crlDownloadService, never()).downloadCrl(any());
    }

    @Test
    void reload_downloadFailsForOneChain_reportsExceptionTypeWithoutItsMessage() throws Exception {
        stubFailureForFirstChain(new IOException("Connection refused"));
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response = endpoint.reload(null);

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).containsExactly(
                Map.entry(FIRST_CHAIN, new ChainReloadResult(FAILURE, "java.io.IOException")),
                Map.entry(SECOND_CHAIN, result(UPDATED))
        );
        assertThat(downloadedChainNames()).containsExactly(FIRST_CHAIN, SECOND_CHAIN);
    }

    @Test
    void reload_malformedChainName_returnsBadRequestAndDoesNotEchoTheName() throws Exception {
        CrlReloadEndpoint endpoint = new CrlReloadEndpoint(properties, crlDownloadService);

        WebEndpointResponse<Map<String, ChainReloadResult>> response =
                endpoint.reload("bad\nname 2026-01-01 forged log line");

        assertThat(response.getStatus()).isEqualTo(WebEndpointResponse.STATUS_BAD_REQUEST);
        assertThat(response.getBody()).isEmpty();
        verify(crlDownloadService, never()).downloadCrl(any());
    }

    private void stubFailureForFirstChain(Exception exception) throws IOException {
        doAnswer(invocation -> {
            CertificateChain chain = invocation.getArgument(0);
            if (FIRST_CHAIN.equals(chain.name())) {
                throw exception;
            }
            return UPDATED;
        }).when(crlDownloadService).downloadCrl(any());
    }

    private List<String> downloadedChainNames() throws IOException {
        ArgumentCaptor<CertificateChain> captor = ArgumentCaptor.forClass(CertificateChain.class);
        verify(crlDownloadService, atLeastOnce()).downloadCrl(captor.capture());
        return captor.getAllValues().stream().map(CertificateChain::name).toList();
    }

    private static ChainReloadResult result(CrlDownloadResult result) {
        return new ChainReloadResult(result, null);
    }

    private static CertificateChain chain(String name) {
        return new CertificateChain(name, null, CrlDownloadUtils.createCrlDownload());
    }
}