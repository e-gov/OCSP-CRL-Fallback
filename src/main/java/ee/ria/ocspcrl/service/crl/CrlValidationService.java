package ee.ria.ocspcrl.service.crl;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.config.CrlConfigurationProperties.CertificateChain;
import ee.ria.ocspcrl.exception.CrlValidationException;
import ee.ria.ocspcrl.service.FileService;
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    private final FileService fileService;

    public void validateCrl(String chainName, byte[] crl) {
        try {
            log.info("Validating CRL: {}", chainName);
            X509CRLHolder crlHolder = new X509CRLHolder(crl);
            validateSignature(crlHolder, chainName);
            validateNextUpdate(crlHolder, chainName);
            log.info("CRL is valid: {}", chainName);
            // TODO AUT-2455 Move this operation to CrlDownloadService
            log.info("Moving CRL from tmp to validated directory: {}", chainName);
            fileService.moveValidCrl(chainName);
            log.info("Moved CRL to validated directory: {}",  chainName);
        } catch (CrlValidationException e) {
            log.error("Failed to validate CRL for {}: {}", chainName, e.getMessage());
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log();
        }
    }

    private void validateSignature(X509CRLHolder crlHolder, String chainName) {
        CertificateChain certificateChain = properties.certificateChain(chainName);
        X509CertificateHolder certificate = certificateChain.issuerCertificate();

        ContentVerifierProvider verifierProvider;
        try {
            // TODO Explore BcContentVerifierProviderBuilder options. This would also make Security.addProvider unnecessary.
            verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(certificate);
        } catch (OperatorCreationException | CertificateException e) {
            // TODO AUT-2455 Review what to catch and where
            log.atWarn()
                    .setCause(e)
                    .log("Failed to build a ContentVerifierProvider");
            throw new RuntimeException(e);
        }

        try {
            if (!crlHolder.isSignatureValid(verifierProvider)) {
                throw new CrlValidationException("CRL signature is not valid");
            }
        } catch (CertException e) {
            // TODO AUT-2455 Review what to catch and where
            log.atWarn()
                    .setCause(e)
                    .log("Signature cannot be processed for chain {}", chainName);
            throw new RuntimeException(e);
        }
    }

    private void validateNextUpdate(X509CRLHolder crlHolder, String chainName) throws IOException {
        X509CRLHolder previousValidatedCrl = getPreviousCrl(chainName);
        if (previousValidatedCrl == null)
            return;

        Date newNextUpdate = crlHolder.getNextUpdate();
        Date previousNextUpdate = previousValidatedCrl.getNextUpdate();

        if (newNextUpdate == null || previousNextUpdate == null) {
            return;
        }

        if (!newNextUpdate.after(previousNextUpdate)) {
            throw new CrlValidationException("New Next Update is not after the previous one");
        }
    }

    // TODO AUT-2455 Handle loading previous CRL and remove this method
    private X509CRLHolder getPreviousCrl(String chainName) throws IOException {
        Path previousValidatedCrlPath = Path.of("/var/cache/ocspcrl/crl" + chainName + "crl");

        if (Files.notExists(previousValidatedCrlPath)) {
            return null;
        }

        byte[] previousCrlBytes = Files.readAllBytes(previousValidatedCrlPath);
        return new X509CRLHolder(previousCrlBytes);
    }
}
