package ee.ria.ocspcrl.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Date;

@AllArgsConstructor
public class CertificateRevokedException extends RuntimeException {

    @Getter
    private Date revocationTime;

    // This value must represent a CRLReason.
    @Getter
    private Integer revocationReason;
}
