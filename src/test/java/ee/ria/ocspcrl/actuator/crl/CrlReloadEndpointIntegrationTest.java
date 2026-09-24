package ee.ria.ocspcrl.actuator.crl;

import ee.ria.ocspcrl.BaseIntegrationTest;
import ee.ria.ocspcrl.service.crl.CrlDownloadService;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static ee.ria.ocspcrl.actuator.crl.CrlReloadEndpoint.RESULT_UNKNOWN_CHAIN;
import static ee.ria.ocspcrl.service.crl.CrlDownloadService.CrlDownloadResult.UPDATED;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;

class CrlReloadEndpointIntegrationTest extends BaseIntegrationTest {

    private static final String FIRST_CONFIGURED_CHAIN = "test_esteid2018";
    private static final String SECOND_CONFIGURED_CHAIN = "test_esteid2025";

    // Mocked because CrlLoadingBootstrap also invokes downloadCrl on ApplicationReadyEvent.
    @MockitoBean
    private CrlDownloadService crlDownloadService;

    @BeforeEach
    void stubDownloadResult() throws Exception {
        when(crlDownloadService.downloadCrl(any())).thenReturn(UPDATED);
    }

    @Test
    void whenNoChainGiven_everyConfiguredChainIsReloaded() {
        given()
                .accept(ContentType.JSON)
                .contentType(ContentType.JSON)
                .body("{}")
                .when()
                .post("/actuator/crlreload")
                .then()
                .statusCode(OK.value())
                .body("$", aMapWithSize(2))
                .body(FIRST_CONFIGURED_CHAIN, equalTo(UPDATED.name()))
                .body(SECOND_CONFIGURED_CHAIN, equalTo(UPDATED.name()));
    }

    @Test
    void whenChainGiven_onlyThatChainIsReloaded() {
        given()
                .accept(ContentType.JSON)
                .contentType(ContentType.JSON)
                .body("{\"chain\":\"" + FIRST_CONFIGURED_CHAIN + "\"}")
                .when()
                .post("/actuator/crlreload")
                .then()
                .statusCode(OK.value())
                .body("$", aMapWithSize(1))
                .body(FIRST_CONFIGURED_CHAIN, equalTo(UPDATED.name()));
    }

    @Test
    void whenUnknownChainGiven_notFoundReturned() {
        given()
                .accept(ContentType.JSON)
                .contentType(ContentType.JSON)
                .body("{\"chain\":\"no_such_chain\"}")
                .when()
                .post("/actuator/crlreload")
                .then()
                .statusCode(NOT_FOUND.value())
                .body("no_such_chain", equalTo(RESULT_UNKNOWN_CHAIN));
    }
}
