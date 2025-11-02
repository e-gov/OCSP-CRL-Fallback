package ee.ria.ocspcrl.service;

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
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

@Slf4j
class OcspServiceTest {

    public static final X509CertificateHolder ISSUER_CERTIFICATE =
            CertificateUtils.loadPemCertificateFromClasspath("/certificates/eid/testEEGovCA2025.crt.pem");

    private final OcspService ocspService = new OcspService();

    private final DigestCalculator sha1DigestCalculator =
            new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    OcspServiceTest() throws OperatorCreationException {}

    @Nested
    class HandleRequest {

        @SuppressWarnings("DataFlowIssue")
        @Test
        void whenNullOcspRequest_nullPointerExceptionThrown() {
            assertThatNullPointerException()
                    .isThrownBy(() -> ocspService.handleRequest(null, ISSUER_CERTIFICATE));
        }

        @SuppressWarnings("DataFlowIssue")
        @SneakyThrows
        @Test
        void whenNullIssuerCertificate_nullPointerExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder().build();

            assertThatNullPointerException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, null));
        }

        @SneakyThrows
        @Test
        /* Bouncy Castle does not provide a simple way to have a version other than `1`, so we need to do some trickery
         * in order to have a different version number.
         */
        void whenInvalidOcspVersion_illegalArgumentExceptionThrown() {
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

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenEmptyRequestList_illegalArgumentExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .build();

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenMultipleCertificateRequests_illegalArgumentExceptionThrown() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.TWO))
                    .build();

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenUnsupportedHashAlgorithm_illegalArgumentExceptionThrown() {
            DigestCalculator md5DigestCalculator =
                    new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(PKCSObjectIdentifiers.md5));
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(md5DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .build();
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenInvalidIssuerNameHash_illegalArgumentExceptionThrown() {
            CertID valid = new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE)
                    .toASN1Primitive();
            CertID actual = new CertID(
                    valid.getHashAlgorithm(),
                    new DEROctetString(new byte[valid.getIssuerNameHash().getOctetsLength()]),
                    valid.getIssuerKeyHash(),
                    valid.getSerialNumber());
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(actual))
                    .build();

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenInvalidIssuerKeyHash_illegalArgumentExceptionThrown() {
            CertID valid = new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE)
                    .toASN1Primitive();
            CertID actual = new CertID(
                    valid.getHashAlgorithm(),
                    valid.getIssuerNameHash(),
                    new DEROctetString(new byte[valid.getIssuerKeyHash().getOctetsLength()]),
                    valid.getSerialNumber());
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(actual))
                    .build();

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE));
        }

        @SneakyThrows
        @Test
        void whenValidOcspRequest_nullReturned() {
            OCSPReq ocspRequest = new OCSPReqBuilder()
                    .addRequest(new CertificateID(sha1DigestCalculator, ISSUER_CERTIFICATE, BigInteger.ONE))
                    .build();

            assertThat(ocspService.handleRequest(ocspRequest, ISSUER_CERTIFICATE))
                    .isNull();
        }
    }

}
