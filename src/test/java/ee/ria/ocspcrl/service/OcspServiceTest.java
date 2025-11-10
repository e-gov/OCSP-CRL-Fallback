package ee.ria.ocspcrl.service;

import ee.ria.ocspcrl.assertion.OCSPRespAssert;
import ee.ria.ocspcrl.util.CertificateUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static ee.ria.ocspcrl.service.OcspService.createNonceExtension;
import static ee.ria.ocspcrl.service.OcspService.getNonce;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.when;

@Slf4j
@ExtendWith(MockitoExtension.class)
class OcspServiceTest {

    private static final X509CertificateHolder ISSUER_CERTIFICATE =
            CertificateUtils.loadPemCertificateFromClasspath("/certificates/eid/testEEGovCA2025.crt.pem");
    private static final X509Certificate SIGNING_CERTIFICATE =
            CertificateUtils.loadPemAsX509CertificateFromClasspath("/certificates/ocsp/ocsp.crt.pem");
    private static final String SIGNING_CERTIFICATE_DN = "CN=test-ocsp";
    private static final PrivateKey SIGNING_KEY =
            CertificateUtils.loadECPrivateKeyFromClasspath("/certificates/ocsp/ocsp.key.pem");
    private static final byte[] NONCE = "test-nonce-value".getBytes(StandardCharsets.UTF_8);

    private final DigestCalculator sha1DigestCalculator =
            new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    @Mock
    private OcspKeyService keyService;
    private OcspService ocspService;

    OcspServiceTest() throws OperatorCreationException {}

    @BeforeEach
    void setUp() {
        ocspService = new OcspService(keyService);
    }

    @Nested
    class HandleRequest {

        @SneakyThrows
        @Test
        void whenNullOcspRequest_malformedRequestReturned() {
            OCSPResp ocspResponse = ocspService.handleRequest(null, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenNullIssuerCertificate_malformedRequestReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder().build();

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, null);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        /* Bouncy Castle does not provide a simple way to have a version other than `1`, so we need to do some trickery
         * in order to have a different version number.
         */
        void whenInvalidOcspVersion_malformedRequestReturned() {
            // Version numbers are offset, meaning using `0` would mean version `1`.
            ASN1Integer v2 = new ASN1Integer(1);
            OCSPReq validOcspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .build();

            OCSPRequest ocspRequestPrimitive;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(validOcspRequest.getEncoded())){
                ocspRequestPrimitive = OCSPRequest.getInstance(asn1InputStream.readObject());
            }
            TBSRequest tbsRequest = ocspRequestPrimitive.getTbsRequest();
            ReflectionTestUtils.setField(tbsRequest, "version", v2);
            OCSPReq ocspRequest = new OCSPReq(ocspRequestPrimitive);

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenEmptyRequestList_malformedRequestReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .build();

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenMultipleCertificateRequests_malformedRequestReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.TWO))
                    .build();

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenUnsupportedHashAlgorithm_malformedRequestReturned() {
            DigestCalculator md5DigestCalculator =
                    new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5));
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(md5DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .build();

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenInvalidIssuerNameHash_unknownStatusReturned() {
            CertID valid = new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE)
                    .toASN1Primitive();
            CertID actual = new CertID(
                    valid.getHashAlgorithm(),
                    new DEROctetString(new byte[valid.getIssuerNameHash().getOctetsLength()]),
                    valid.getIssuerKeyHash(),
                    valid.getSerialNumber());
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(actual))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();
            when(keyService.getOcspSigningCert()).thenReturn(SIGNING_CERTIFICATE);
            when(keyService.getOcspSigningKey()).thenReturn(SIGNING_KEY);

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.SUCCESSFUL)
                    .hasSigningCertificateSubject(SIGNING_CERTIFICATE_DN)
                    .hasResponderIdByName(SIGNING_CERTIFICATE_DN)
                    .hasProducedAtWithinLastHour()
                    .hasNonce(getNonce(ocspRequest))
                    .hasCertificateStatusUnknown();
        }

        @SneakyThrows
        @Test
        void whenInvalidIssuerKeyHash_malformedRequestReturned() {
            CertID valid = new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE)
                    .toASN1Primitive();
            CertID actual = new CertID(
                    valid.getHashAlgorithm(),
                    valid.getIssuerNameHash(),
                    new DEROctetString(new byte[valid.getIssuerKeyHash().getOctetsLength()]),
                    valid.getSerialNumber());
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(actual))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();
            when(keyService.getOcspSigningCert()).thenReturn(SIGNING_CERTIFICATE);
            when(keyService.getOcspSigningKey()).thenReturn(SIGNING_KEY);

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.SUCCESSFUL)
                    .hasSigningCertificateSubject(SIGNING_CERTIFICATE_DN)
                    .hasResponderIdByName(SIGNING_CERTIFICATE_DN)
                    .hasProducedAtWithinLastHour()
                    .hasNonce(getNonce(ocspRequest))
                    .hasCertificateStatusUnknown();
        }

        @SneakyThrows
        @Test
        void whenNonceEmpty_malformedRequestReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .setRequestExtensions(createNonceExtension(new byte[]{}))
                    .build();

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.MALFORMED_REQUEST)
                    .hasNoResponseObject();
        }

        @SneakyThrows
        @Test
        void whenKeyServiceIsNull_NullPointerExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();

            assertThatNullPointerException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenSigningKeyIsNull_NullPointerExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();
            when(keyService.getOcspSigningCert()).thenReturn(SIGNING_CERTIFICATE);

            assertThatExceptionOfType(OperatorCreationException.class)
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE))
                    .withMessageContaining("cannot create signer: cannot identify EC private key");
        }

        @SneakyThrows
        @Test
        void whenSigningCertificateIsNull_NullPointerExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();

            assertThatNullPointerException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE))
                    .withMessageContaining("\"signingCert\" is null");
        }

        @SneakyThrows
        @Test
        void whenValidOcspRequest_SuccessfulOcspResponseReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .setRequestExtensions(createNonceExtension(NONCE))
                    .build();
            when(keyService.getOcspSigningCert()).thenReturn(SIGNING_CERTIFICATE);
            when(keyService.getOcspSigningKey()).thenReturn(SIGNING_KEY);

            OCSPResp ocspResponse = ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE);

            OCSPRespAssert.assertThat(ocspResponse)
                    .hasResponseStatus(OCSPResp.SUCCESSFUL)
                    .hasCertificateStatusGood()
                    .hasSigningCertificateSubject(SIGNING_CERTIFICATE_DN)
                    .hasResponderIdByName(SIGNING_CERTIFICATE_DN)
                    .hasProducedAtWithinLastHour()
                    .hasNonce(getNonce(ocspRequest));
        }
    }
}
