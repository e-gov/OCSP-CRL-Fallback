package ee.ria.ocspcrl.controller.ocsp;

import ee.ria.ocspcrl.BaseIntegrationTest;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CrlDownload;
import ee.ria.ocspcrl.service.OcspService;
import ee.ria.ocspcrl.util.CertificateUtils;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.convention.TestBean;

import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static ee.ria.ocspcrl.config.oscp.OcspReqHttpMessageConverter.OCSP_REQUEST_CONTENT_TYPE;
import static ee.ria.ocspcrl.config.oscp.OcspRespHttpMessageConverter.OCSP_RESPONSE_CONTENT_TYPE;
import static ee.ria.ocspcrl.util.MockitoUtil.ANSWER_THROW_EXCEPTION;
import static io.restassured.RestAssured.given;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;
import static org.springframework.http.HttpStatus.NOT_ACCEPTABLE;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.NOT_IMPLEMENTED;
import static org.springframework.http.HttpStatus.UNSUPPORTED_MEDIA_TYPE;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

class OcspControllerTest extends BaseIntegrationTest {

    private static final String CERTIFICATE_CHAIN_NAME = "esteid2025";
    private static final X509CertificateHolder ISSUER_CERTIFICATE =
            CertificateUtils.loadPemCertificateFromClasspath("/certificates/eid/testEEGovCA2025.crt.pem");
    private static OcspService ocspService;

    @TestBean
    private OcspController ocspController;

    private final DigestCalculator digestCalculator =
            new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    OcspControllerTest() throws OperatorCreationException {}

    @SneakyThrows
    private static OcspController ocspController() {
        ocspService = mock(OcspService.class, ANSWER_THROW_EXCEPTION);
        CertificateChain certificateChain = new CertificateChain(
                CERTIFICATE_CHAIN_NAME,
                ISSUER_CERTIFICATE,
                new CrlDownload(
                        URI.create("https://ria.ee/esteid2025.crl").toURL(),
                        Duration.ofMillis(1),
                        "<not-used>")
        );
        CrlConfigurationProperties crlConfigurationProperties = new CrlConfigurationProperties(
                Duration.ofMillis(1),
                List.of(certificateChain),
                mock(Path.class, ANSWER_THROW_EXCEPTION));
        return new OcspController(
                ocspService,
                crlConfigurationProperties
        );
    }

    @AfterEach
    void tearDown() {
        reset(ocspService);
    }

    @Nested
    class HandleOcspRequest {

        @Test
        void whenInvalidHttpMethod_methodNotAllowedReturned() {
            given()
                    // Omitting `.noContentType()` leads to a weird `NullPointerException` deep inside REST Assured
                    .noContentType()
                    .when()
                    .get("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(METHOD_NOT_ALLOWED.value());
        }

        @Test
        void whenInvalidAcceptHeader_notAcceptableReturned() {
            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE)
                    .when()
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(NOT_ACCEPTABLE.value());
        }

        @Test
        void whenInvalidContentTypeHeader_unsupportedMediaTypeReturned() {
            given()
                    .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
                    .when()
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(UNSUPPORTED_MEDIA_TYPE.value());
        }


        @Test
        void whenRequestBodyNotValidOcspRequest_badRequestReturned() {
            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
                    .when()
                    .body("<not-a-valid-OCSP-request>".getBytes(UTF_8))
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(BAD_REQUEST.value());
        }

        @SneakyThrows
        @Test
        void whenInvalidCertificateChainId_notFoundReturned() {
            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
                    .when()
                    .body(validOcspRequest().getEncoded())
                    .post("/ocsp/{chainId}", "invalid-chainId")
                    .then()
                    .statusCode(NOT_FOUND.value());
        }

        @Test
        @SneakyThrows
        void whenServiceCallFails_badRequestReturned() {
            doThrow(new IllegalArgumentException("OcspService: invalid OCSP request"))
                    .when(ocspService).handleRequest(any(), any());

            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
                    .when()
                    .body(validOcspRequest().getEncoded())
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(BAD_REQUEST.value());
        }

        @SneakyThrows
        @Test
        void whenServiceCallSucceeds_notImplementedReturned() {
            doReturn(null)
                    .when(ocspService).handleRequest(any(), any());

            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, OCSP_RESPONSE_CONTENT_TYPE)
                    .when()
                    .body(validOcspRequest().getEncoded())
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(NOT_IMPLEMENTED.value());
        }

        @SneakyThrows
        @Test
        void whenAcceptHeaderValueIsAny_notImplementedReturned() {
            doReturn(null)
                    .when(ocspService).handleRequest(any(), any());

            given()
                    .header(HttpHeaders.CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
                    .header(HttpHeaders.ACCEPT, ALL_VALUE)
                    .when()
                    .body(validOcspRequest().getEncoded())
                    .post("/ocsp/{chainId}", CERTIFICATE_CHAIN_NAME)
                    .then()
                    .statusCode(NOT_IMPLEMENTED.value());
        }

    }

    @SneakyThrows
    private OCSPReq validOcspRequest() {
        CertificateID certificateId = new CertificateID(digestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE);
        return new OCSPReqBuilder()
                .addRequest(certificateId)
                .build();
    }

}
