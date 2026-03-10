package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.CrlCache;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.exception.CrlValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.stereotype.Service;

import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlValidationService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final CrlConfigurationProperties properties;
    private final CrlCache crlCache;

    public boolean shouldUse(String chainName, X509CRLHolder crlHolder) {
        try {
            log.debug("Validating CRL: {}", chainName);
            validateSignature(crlHolder, chainName);
        } catch (CrlValidationException e) {
            log.warn("Failed to validate CRL for {}: {}", chainName, e.getMessage());
            return false;
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to validate CRL for {}", chainName);
            return false;
        }
        return validateNextUpdate(crlHolder, chainName);
    }

    private void validateSignature(X509CRLHolder crlHolder, String chainName) {
        CertificateChain certificateChain = properties.certificateChain(chainName);
        X509CertificateHolder certificate = certificateChain.issuerCertificate();

        ContentVerifierProvider verifierProvider;
        try {
            // TODO Explore BcContentVerifierProviderBuilder options.
            //  This would also make Security.addProvider unnecessary.
            verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(certificate);

            if (!crlHolder.isSignatureValid(verifierProvider)) {
                throw new CrlValidationException("CRL signature is not valid");
            }
        } catch (OperatorCreationException | CertificateException | CertException e) {
            // TODO AUT-2380 Error or warn?
            log.atWarn()
                    .setCause(e)
                    .log();
        }
    }

    private boolean validateNextUpdate(X509CRLHolder crlHolder, String chainName) {
        X509CRLHolder previousValidatedCrl = crlCache.getCrl(chainName);
        if (previousValidatedCrl == null)
            return true;

        Date newNextUpdate = crlHolder.getNextUpdate();
        Date previousNextUpdate = previousValidatedCrl.getNextUpdate();

        if (newNextUpdate == null || previousNextUpdate == null) {
            return true;
        }
        if (newNextUpdate.before(previousNextUpdate)) {
            log.warn("New Next Update is before the previous one");
            return false;
        }
        return !newNextUpdate.equals(previousNextUpdate);
    }
}
