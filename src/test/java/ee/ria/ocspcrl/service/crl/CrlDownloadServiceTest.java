package ee.ria.ocspcrl.service.crl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.ocspcrl.BaseIntegrationTest;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.gateway.CrlGateway;
import ee.ria.ocspcrl.gateway.CrlGatewayFactory;
import ee.ria.ocspcrl.service.FileIoService;
import ee.ria.ocspcrl.service.FileService;
import ee.ria.ocspcrl.util.CertificateUtils;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.net.ssl.SSLContext;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

// TODO Reorganize tests.
class CrlDownloadServiceTest extends BaseIntegrationTest {

    public static final ObjectMapper jsonMapper = new ObjectMapper();

    private static final String TEST_CHAIN_NAME = "test_esteid1111";
    private static final String STORES_PASSWORD = "password";
    private static final String CRL_BUNDLE_NAME = "test_esteid1111-tls";
    private static final Path TMP_DIR_PATH = Path.of("/tmp/path");
    private static final Path CRL_DIR_PATH = Path.of("/crl/path");

    private static final String RELATIVE_CRL_PATH = "/chain1.crl";
    private static final byte[] DUMMY_CRL_CONTENT = "This is a dummy CRL file.".getBytes(StandardCharsets.UTF_8);

    private static WireMockServer wireMockServer;
    private static Path crlBundleTrustStorePath;
    private static SSLContext originalDefaultContext;

    @Mock
    private FileIoService fileIoService;

    @Autowired
    private CrlGatewayFactory crlGatewayFactory;

    @Mock
    private CrlValidationService crlValidationService;

    @DynamicPropertySource
    private static void dynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.ssl.bundle.jks." + CRL_BUNDLE_NAME + ".truststore.location",
                () -> "file:" + crlBundleTrustStorePath.toAbsolutePath());
        registry.add("spring.ssl.bundle.jks." + CRL_BUNDLE_NAME + ".truststore.password", () -> STORES_PASSWORD);
        registry.add("spring.ssl.bundle.jks." + CRL_BUNDLE_NAME + ".truststore.type", () -> "PKCS12");
    }

    @BeforeAll
    static void genericSetUp() throws Exception {
        originalDefaultContext = SSLContext.getDefault();
        Path tempDir = Files.createTempDirectory("wiremock");
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = createKeyPair();
        X509Certificate serverCertificate = createServerCertificate(keyPair);
        Path keystorePath = configureServerKeystore(tempDir, keyPair, serverCertificate);
        crlBundleTrustStorePath = configureClientTruststore(tempDir, serverCertificate);
        startWireMock(keystorePath);
    }

    @AfterAll
    static void genericTearDown() {
        wireMockServer.stop();
    }

    @AfterEach
    void tearDown() {
        // Some tests modify the SSLContext. Restore the original context after each test.
        if (originalDefaultContext != null) {
            SSLContext.setDefault(originalDefaultContext);
        }
    }

    @Test
    void downloadAllCrls_fromHttpUrl_writesCrlToFile() throws IOException {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(DUMMY_CRL_CONTENT)));
        URL url = getHttpUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, null);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        Path expectedPath = TMP_DIR_PATH.resolve(TEST_CHAIN_NAME + ".crl.tmp");
        verify(fileIoService, times(1)).writeToFile(eq(expectedPath), aryEq(DUMMY_CRL_CONTENT));
    }

    @Test
    void downloadAllCrls_fromHttpsUrlHavingCertInBundle_writesCrlToFile() throws IOException {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(DUMMY_CRL_CONTENT)));
        URL url = getHttpsUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, CRL_BUNDLE_NAME);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        Path expectedPath = TMP_DIR_PATH.resolve(TEST_CHAIN_NAME + ".crl.tmp");
        verify(fileIoService, times(1)).writeToFile(eq(expectedPath), aryEq(DUMMY_CRL_CONTENT));
    }

    @Test
    void downloadAllCrls_fromHttpsUrlHavingNoTruststoreConfiguredAndCertNotInDefaultTruststore_doesNotWriteToFile() throws IOException {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(DUMMY_CRL_CONTENT)));
        URL url = getHttpsUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, null);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        verify(fileIoService, never()).writeToFile(any(), aryEq(DUMMY_CRL_CONTENT));
    }

    @Test
    void downloadAllCrls_fromHttpsUrlHavingNoTruststoreConfiguredAndCertInDefaultTruststore_writesCrlToFile() throws Exception {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(DUMMY_CRL_CONTENT)));
        CertificateUtils.addCertificatesFromSpecifiedTruststoreToDefaultTruststore(crlBundleTrustStorePath, STORES_PASSWORD);
        URL url = getHttpsUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, null);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        Path expectedPath = TMP_DIR_PATH.resolve(TEST_CHAIN_NAME + ".crl.tmp");
        verify(fileIoService, times(1)).writeToFile(eq(expectedPath), aryEq(DUMMY_CRL_CONTENT));
    }

    @Test
    void downloadAllCrls_fromHttpUrlNotModifiedResponseStatus_doesNotWriteToFile() throws IOException {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(304)
                        .withBody(DUMMY_CRL_CONTENT)));
        URL url = getHttpUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, null);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        verify(fileIoService, never()).writeToFile(any(), any());
    }

    @Test
    void downloadAllCrls_fromHttpUrl_writesHeadersToFile() throws IOException {
        wireMockServer.stubFor(get(RELATIVE_CRL_PATH)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("ETag", "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"")
                        .withHeader("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
                        .withBody(DUMMY_CRL_CONTENT)));
        URL url = getHttpUrl(RELATIVE_CRL_PATH);
        CrlConfigurationProperties properties = createConfigurationProperties(url, null);
        FileService fileService = new FileService(fileIoService, properties);
        CrlDownloadService crlDownloadService = new CrlDownloadService(properties, fileService, crlGatewayFactory, crlValidationService);

        crlDownloadService.downloadAllCrls();

        Path expectedPath = TMP_DIR_PATH.resolve(TEST_CHAIN_NAME + ".headers.tmp");
        CrlGateway.CrlCacheKey crlCacheKey = new CrlGateway.CrlCacheKey(
                "Wed, 21 Oct 2015 07:28:00 GMT",
                "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"");
        byte[] keyBytes = jsonMapper.writeValueAsBytes(crlCacheKey);
        verify(fileIoService, times(1)).writeToFile(eq(expectedPath), aryEq(keyBytes));
    }

    private static Path configureServerKeystore(Path tempDir, KeyPair keyPair, X509Certificate serverCertificate) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        Path keystorePath = tempDir.resolve("keystore.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("key1", keyPair.getPrivate(), STORES_PASSWORD.toCharArray(), new Certificate[]{serverCertificate});
        try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
            keyStore.store(fos, STORES_PASSWORD.toCharArray());
        }
        return keystorePath;
    }

    private static KeyPair createKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate createServerCertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException {
        X500Name issuer = new X500Name("CN=localhost, O=Test, L=Test, C=EE");
        BigInteger serialNumber = BigInteger.valueOf(12345);
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(1, ChronoUnit.HOURS));
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, issuer, keyPair.getPublic()
        );
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
    }

    private static Path configureClientTruststore(Path tempDir, X509Certificate certificate) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        Path clientTrustStorePath = tempDir.resolve("truststore.p12");
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("cert1", certificate);
        try (FileOutputStream outputStream = new FileOutputStream(clientTrustStorePath.toFile())) {
            trustStore.store(outputStream, STORES_PASSWORD.toCharArray());
        }
        return clientTrustStorePath;
    }

    private static void startWireMock(Path keystorePath) {
        wireMockServer = new WireMockServer(WireMockConfiguration.options()
                .dynamicPort()
                .dynamicHttpsPort()
                .keystorePath(keystorePath.toString())
                .keystorePassword(STORES_PASSWORD)
                .keyManagerPassword(STORES_PASSWORD)
                // WireMock alters ETags: https://github.com/wiremock/wiremock/issues/2822, which breaks some tests.
                .gzipDisabled(true)
        );
        wireMockServer.start();
    }

    private static URL getHttpUrl(String relativePath) throws MalformedURLException {
        return new URL("http://localhost:" + wireMockServer.port() + relativePath);
    }

    private static URL getHttpsUrl(String relativePath) throws MalformedURLException {
        return new URL(wireMockServer.url(relativePath));
    }

    @SneakyThrows
    private static CrlConfigurationProperties createConfigurationProperties(
            URL url,
            String tlsTruststoreBundle) {
        CrlConfigurationProperties.CrlDownload crlDownload =
                new CrlConfigurationProperties.CrlDownload(
                        url,
                        Duration.ofSeconds(5),
                        tlsTruststoreBundle
                );
        CrlConfigurationProperties.CertificateChain chain =
                new CrlConfigurationProperties.CertificateChain(
                        TEST_CHAIN_NAME,
                        null,
                        crlDownload
                );
        return new CrlConfigurationProperties(
                Duration.ofSeconds(30),
                List.of(chain),
                TMP_DIR_PATH,
                CRL_DIR_PATH
        );
    }
}

