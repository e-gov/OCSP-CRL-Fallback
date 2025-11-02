package ee.ria.ocspcrl;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.configuration.TestSchedulingConfiguration;
import io.restassured.RestAssured;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.http.ContentType;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static ee.ria.ocspcrl.config.oscp.OcspReqHttpMessageConverter.OCSP_REQUEST_CONTENT_TYPE;
import static io.restassured.config.EncoderConfig.encoderConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@ExtendWith(MockitoExtension.class)
@Import({MockPropertyBeanConfiguration.class, TestSchedulingConfiguration.class})
@SpringBootTest(webEnvironment = RANDOM_PORT)
@ActiveProfiles("test")
public abstract class BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private CrlConfigurationProperties crlConfigurationProperties;

    @BeforeAll
    static void beforeAll() {
        RestAssured.baseURI = "https://localhost";
        RestAssured.useRelaxedHTTPSValidation();
        RestAssured.config()
                .encoderConfig(encoderConfig().encodeContentTypeAs(OCSP_REQUEST_CONTENT_TYPE, ContentType.TEXT));
        RestAssured.filters(
                new RequestLoggingFilter(LogDetail.ALL),
                new ResponseLoggingFilter(LogDetail.ALL)
        );
    }

    @SneakyThrows
    @BeforeEach
    void setUp() {
        RestAssured.port = port;
    }

}
