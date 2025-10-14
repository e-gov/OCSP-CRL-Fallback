package ee.ria.ocspcrl.util;

import lombok.experimental.UtilityClass;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@UtilityClass
public class CertificateUtils {

    private static final String JAVA_DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    // NB! Using this method modifies the SSLContext and might cause unexpected behaviour in all the tests that run
    // after calling this method. To avoid this, backup the original SSLContext and restore it afterward:
    //
    // private static SSLContext originalDefaultContext;              // Static variable to hold the original SSLContext
    // originalDefaultContext = SSLContext.getDefault();              // Backup SSLContext before using this method
    // addCertificatesFromSpecifiedTruststoreToDefaultTruststore(...) // Use the method
    // SSLContext.setDefault(originalDefaultContext);                 // Restore SSLContext after using this method
    public static void addCertificatesFromSpecifiedTruststoreToDefaultTruststore(Path customTruststorePath, String customTruststorePassword) throws Exception {
        KeyStore defaultTrustStore = getDefaultTrustStore();
        KeyStore customTrustStore = loadCustomTruststore(customTruststorePath, customTruststorePassword);
        updateDefaultTruststore(customTrustStore, defaultTrustStore);
        SSLContext newContext = createNewSslContext(defaultTrustStore);
        SSLContext.setDefault(newContext);
    }

    private static SSLContext createNewSslContext(KeyStore defaultTrustStore) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(defaultTrustStore);
        SSLContext newContext = SSLContext.getInstance("TLS");
        newContext.init(null, tmf.getTrustManagers(), null);
        return newContext;
    }

    private static void updateDefaultTruststore(KeyStore customTrustStore, KeyStore defaultTrustStore) throws KeyStoreException {
        Enumeration<String> aliases = customTrustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (customTrustStore.isCertificateEntry(alias)) {
                X509Certificate cert = (X509Certificate) customTrustStore.getCertificate(alias);
                if (cert != null) {
                    defaultTrustStore.setCertificateEntry("custom-" + alias, cert);
                }
            }
        }
    }

    private static KeyStore loadCustomTruststore(Path customTrustStorePath, String customTruststorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore customTrustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream inputStream = new FileInputStream(customTrustStorePath.toFile())) {
            char[] password = null;
            if (customTruststorePassword != null) {
                password = customTruststorePassword.toCharArray();
            }
            customTrustStore.load(inputStream, password);
        }
        return customTrustStore;
    }

    private static KeyStore getDefaultTrustStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        String defaultTruststorePath = System.getProperty("java.home") + "/lib/security/cacerts";
        char[] defaultPassword = JAVA_DEFAULT_TRUSTSTORE_PASSWORD.toCharArray();

        KeyStore defaultTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream inputStream = new FileInputStream(defaultTruststorePath)) {
            defaultTrustStore.load(inputStream, defaultPassword);
        }
        return defaultTrustStore;
    }
}
