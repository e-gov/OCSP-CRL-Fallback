package ee.ria.ocspcrl.util;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@UtilityClass
public class CertificateUtils {

    private static final String JAVA_DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

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

    public static X509CertificateHolder loadPemCertificateFromClasspath(String path) {
        URL resourceUrl = CertificateUtils.class.getResource(path);
        if (resourceUrl == null) {
            throw new IllegalArgumentException("Could not find certificate \"%s\" on classpath".formatted(path));
        }
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(resourceUrl.openStream()))) {
            Object parsedObject = pemParser.readObject();
            if (!(parsedObject instanceof X509CertificateHolder certificate)) {
                throw new IllegalArgumentException("Resource is not an X.509 certificate");
            }
            return certificate;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Should also support DER format, but this is not tested
    @SneakyThrows
    public static X509Certificate loadPemAsX509CertificateFromClasspath(String path) {
        URL resourceUrl = CertificateUtils.class.getResource(path);
        if (resourceUrl == null) {
            throw new IllegalArgumentException("Could not find certificate \"%s\" on classpath".formatted(path));
        }

        try (InputStream inputStream = resourceUrl.openStream()) {
            if (inputStream == null) {
                throw new IllegalArgumentException("Could not find certificate \"%s\" on classpath".formatted(path));
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

    @SneakyThrows
    public static PrivateKey loadECPrivateKeyFromClasspath(String path) {
        URL resourceUrl = CertificateUtils.class.getResource(path);
        if (resourceUrl == null) {
            throw new IllegalArgumentException("Could not find certificate \"%s\" on classpath".formatted(path));
        }

        String pem;
        try (InputStream inputStream = resourceUrl.openStream()) {
            if (inputStream == null)
                throw new IllegalArgumentException("Private key file not found in classpath: " + path);
            pem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Extract "EC PARAMETERS" block from PEM file
        Pattern paramsPattern = Pattern.compile(
                "-----BEGIN EC PARAMETERS-----(.*?)-----END EC PARAMETERS-----",
                Pattern.DOTALL
        );
        Matcher paramsMatcher = paramsPattern.matcher(pem);
        if (!paramsMatcher.find()) {
            throw new IllegalArgumentException("EC PARAMETERS block not found in: " + path);
        }

        // Parse curve OID from parameters
        String paramsBase64 = paramsMatcher.group(1).replaceAll("\\s+", "");
        byte[] paramsBytes = Base64.getDecoder().decode(paramsBase64);
        ASN1Primitive paramsAsn1 = ASN1Primitive.fromByteArray(paramsBytes);
        ASN1ObjectIdentifier curveOid;
        if (paramsAsn1 instanceof ASN1ObjectIdentifier oid) {
            curveOid = oid;
        } else {
            throw new IllegalArgumentException("Invalid EC PARAMETERS block — expected OID but got: " + paramsAsn1.getClass());
        }

        // Extract "EC PRIVATE KEY" block from PEM file
        Pattern keyPattern = Pattern.compile(
                "-----BEGIN EC PRIVATE KEY-----(.*?)-----END EC PRIVATE KEY-----",
                Pattern.DOTALL
        );
        Matcher keyMatcher = keyPattern.matcher(pem);
        if (!keyMatcher.find()) {
            throw new IllegalArgumentException("EC PRIVATE KEY block not found in: " + path);
        }

        // Parse private key from Base64
        String keyBase64 = keyMatcher.group(1).replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(ASN1Sequence.getInstance(keyBytes));

        // Wrap the key into PKCS#8 with previously parsed curve OID
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid),
                ecPrivateKey
        );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());

        // Build PrivateKey object
        return KeyFactory.getInstance("EC").generatePrivate(spec);
    }
}
