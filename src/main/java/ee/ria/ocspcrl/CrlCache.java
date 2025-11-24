package ee.ria.ocspcrl;

import org.bouncycastle.cert.X509CRLHolder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CrlCache {

    private final Map<String, X509CRLHolder> crlByChainName = new ConcurrentHashMap<>();

    public X509CRLHolder getCrl(String chainName) {
        return crlByChainName.get(chainName);
    }

    public void updateCrl(String chainName, X509CRLHolder crlHolder) {
        crlByChainName.put(chainName, crlHolder);
    }
}
