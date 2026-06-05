package ee.ria.ocspcrl.exception;

import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class CertificateRevokedException extends RuntimeException {

    @Getter
    private Date revocationTime;

    // This value must represent a CRLReason.
    @Getter
    private Integer revocationReason;
}
