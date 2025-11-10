package ee.ria.ocspcrl.exception;

public class CertificateChainMismatchException extends RuntimeException {

    public CertificateChainMismatchException(String message) {
        super(message);
    }
}
