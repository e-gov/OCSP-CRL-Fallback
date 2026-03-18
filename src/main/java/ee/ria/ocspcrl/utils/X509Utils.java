package ee.ria.ocspcrl.utils;

import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import java.math.BigInteger;

@UtilityClass
public class X509Utils {

    public String getSubjectCN(X509CertificateHolder certificate) {
        return getFirstCN(certificate.getSubject());
    }

    public String getFirstCN(X500Name x500Name) {
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public BigInteger getCrlNumber(X509CRLHolder crlHolder) {
        Extension ext = crlHolder.getExtension(Extension.cRLNumber);
        if (ext == null) {
            return null;
        }
        ASN1Integer asn1Int = ASN1Integer.getInstance(ext.getParsedValue());
        return asn1Int.getValue();
    }
}
