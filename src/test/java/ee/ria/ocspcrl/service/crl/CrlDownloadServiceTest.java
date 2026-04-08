package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.CrlCache;
import ee.ria.ocspcrl.CrlDownloadUtils;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.gateway.CrlGateway;
import ee.ria.ocspcrl.gateway.CrlGatewayFactory;
import ee.ria.ocspcrl.service.FileService;
import lombok.SneakyThrows;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CrlDownloadServiceTest {

    private static final byte[] DUMMY_CRL_CONTENT = "This is a dummy CRL file.".getBytes(StandardCharsets.UTF_8);

    private static byte[] VALID_CRL_CONTENT;

    @Mock
    private FileService fileService;

    @Mock
    private CrlGatewayFactory crlGatewayFactory;

    @Mock
    private CrlValidationService crlValidationService;

    @Mock
    private CrlCache crlCache;

    @Mock
    private CrlGateway gateway;

    private CrlDownloadService crlDownloadService;

    private CrlConfigurationProperties.CertificateChain certificateChain;

    @BeforeAll
    @SneakyThrows
    static void generateCrl() {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(new X500Principal("CN=Test"), Date.from(Instant.now()));
        builder.setNextUpdate(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        VALID_CRL_CONTENT = builder.build(signer).getEncoded();
    }

    @BeforeEach
    void setup() {
        when(crlGatewayFactory.create(any())).thenReturn(gateway);

        crlDownloadService = new CrlDownloadService(fileService, crlGatewayFactory, crlValidationService, crlCache);
        certificateChain = CrlDownloadUtils.createChain();
    }

    @Test
    void downloadCrl_crlCacheHasHeaders_headersAreUsed() throws Exception {
        CrlGateway.CrlHeaders requestHeaders = new CrlGateway.CrlHeaders("test123", "ETag123");
        when(crlCache.getCrlHeaders(CrlDownloadUtils.TEST_CHAIN_NAME)).thenReturn(requestHeaders);
        CrlGateway.CrlHeaders responseHeaders = new CrlGateway.CrlHeaders("response123", "responseETag");
        when(gateway.downloadFile(requestHeaders)).thenReturn(new CrlGateway.NewCrlFileResponse(VALID_CRL_CONTENT, responseHeaders));
        X509CRLHolder crlHolder = new X509CRLHolder(VALID_CRL_CONTENT);
        when(crlValidationService.shouldUse(CrlDownloadUtils.TEST_CHAIN_NAME, crlHolder)).thenReturn(true);

        crlDownloadService.downloadCrl(certificateChain);

        verify(crlCache).getCrlHeaders(CrlDownloadUtils.TEST_CHAIN_NAME);
        verify(crlCache).updateCrlAndHeaders(CrlDownloadUtils.TEST_CHAIN_NAME, crlHolder, responseHeaders);
    }

    @Test
    void downloadCrl_notModifiedResponse_doesNotSerializeToFile() throws Exception {
        when(gateway.downloadFile(any())).thenReturn(new CrlGateway.CrlFileNotModifiedResponse(null));

        crlDownloadService.downloadCrl(certificateChain);

        verify(fileService, never()).serializeToFile(any(), any(), any());
    }

    @Test
    void downloadCrl_newCrlWithNullContent_doesNotSerializeToFile() throws Exception {
        when(gateway.downloadFile(any())).thenReturn(new CrlGateway.NewCrlFileResponse(null, null));

        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> crlDownloadService.downloadCrl(certificateChain))
                .withMessage("Received empty content from URL: http://test.com/chain1.crl");
        verify(fileService, never()).serializeToFile(any(), any(), any());
    }

    @Test
    void downloadCrl_invalidCrlResponseType_doesNotSerializeToFile() throws Exception {
        when(gateway.downloadFile(any())).thenReturn(new InvalidCrlResponse());

        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> crlDownloadService.downloadCrl(certificateChain))
                .withMessage("Unexpected response type: ee.ria.ocspcrl.service.crl.CrlDownloadServiceTest$InvalidCrlResponse");

        verify(fileService, never()).serializeToFile(any(), any(), any());
    }

    @Test
    void downloadCrl_newCrlContent_serializesToFileThenThrows() throws Exception {
        CrlGateway.NewCrlFileResponse response = new CrlGateway.NewCrlFileResponse(DUMMY_CRL_CONTENT, null);
        when(gateway.downloadFile(any())).thenReturn(response);

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> crlDownloadService.downloadCrl(certificateChain))
                .withMessage("corrupted stream - out of bounds length found: 104 >= 25");

        verify(fileService).serializeToFile(eq(CrlDownloadUtils.TEST_CHAIN_NAME), eq(response), eq(FileService.FileType.TEMP));
    }

    @Test
    void downloadCrl_invalidCrlContent_throws() {
        CrlGateway.NewCrlFileResponse response = new CrlGateway.NewCrlFileResponse(DUMMY_CRL_CONTENT, null);
        when(gateway.downloadFile(any())).thenReturn(response);

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> crlDownloadService.downloadCrl(certificateChain))
                .withMessage("corrupted stream - out of bounds length found: 104 >= 25");
    }

    @Test
    void downloadCrl_validCrlContentAndShouldUse_updatesCrlAndHeaders() throws Exception {
        CrlGateway.NewCrlFileResponse response = new CrlGateway.NewCrlFileResponse(VALID_CRL_CONTENT, null);
        when(gateway.downloadFile(any())).thenReturn(response);
        when(crlValidationService.shouldUse(any(), any())).thenReturn(true);

        crlDownloadService.downloadCrl(certificateChain);

        verify(crlCache).updateCrlAndHeaders(eq(CrlDownloadUtils.TEST_CHAIN_NAME), eq(new X509CRLHolder(VALID_CRL_CONTENT)), any());
    }

    @Test
    void downloadCrl_validCrlContentAndShouldNotUse_doesNotUpdateCrlAndHeaders() throws Exception {
        CrlGateway.NewCrlFileResponse response = new CrlGateway.NewCrlFileResponse(VALID_CRL_CONTENT, null);
        when(gateway.downloadFile(any())).thenReturn(response);
        when(crlValidationService.shouldUse(any(), any())).thenReturn(false);

        crlDownloadService.downloadCrl(certificateChain);

        verify(crlCache, never()).updateCrlAndHeaders(any(), any(), any());
    }

    @Test
    void downloadCrl_validCrlContentAndShouldUse_movesCrlAndHeaders() throws Exception {
        CrlGateway.NewCrlFileResponse response = new CrlGateway.NewCrlFileResponse(VALID_CRL_CONTENT, null);
        when(gateway.downloadFile(any())).thenReturn(response);
        when(crlValidationService.shouldUse(any(), any())).thenReturn(true);

        crlDownloadService.downloadCrl(certificateChain);

        verify(fileService).moveValidCrl(eq(CrlDownloadUtils.TEST_CHAIN_NAME));
        verify(fileService).moveHeaders(eq(CrlDownloadUtils.TEST_CHAIN_NAME));
    }

    public record InvalidCrlResponse() implements CrlGateway.CrlResponse {}
}
