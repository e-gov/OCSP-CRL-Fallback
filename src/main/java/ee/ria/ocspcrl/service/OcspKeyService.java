package ee.ria.ocspcrl.service;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Service
@RequiredArgsConstructor
public class OcspKeyService {

    private static final String OCSP_BUNDLE_NAME = "ocsp";
    private final SslBundles sslBundles;
    @Getter
    private PrivateKey ocspSigningKey;
    @Getter
    private X509Certificate ocspSigningCert;

    @PostConstruct
    public void init() throws GeneralSecurityException {
        SslBundle ocspBundle = sslBundles.getBundle(OCSP_BUNDLE_NAME);
        String ocspKeystoreEntryAlias = ocspBundle.getKey().getAlias();
        KeyStore keyStore = ocspBundle.getStores().getKeyStore();
        this.ocspSigningKey = (PrivateKey) keyStore.getKey(ocspKeystoreEntryAlias, null);
        this.ocspSigningCert = (X509Certificate) keyStore.getCertificate(ocspKeystoreEntryAlias);

        if (this.ocspSigningKey == null) {
            throw new IllegalStateException("Failed to find PrivateKey in SslBundle '" + OCSP_BUNDLE_NAME + "' with alias " + ocspKeystoreEntryAlias);
        }
        if (this.ocspSigningCert == null) {
            throw new IllegalStateException("Failed to find X509Certificate in SslBundle '" + OCSP_BUNDLE_NAME + "' with alias " + ocspKeystoreEntryAlias);
        }
    }
}
