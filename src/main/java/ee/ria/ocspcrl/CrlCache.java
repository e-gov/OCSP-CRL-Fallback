package ee.ria.ocspcrl;

import ee.ria.ocspcrl.gateway.CrlGateway;
import org.bouncycastle.cert.X509CRLHolder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CrlCache {

    private final Map<String, CrlInfo> crlInfoByChainName = new ConcurrentHashMap<>();

    public X509CRLHolder getCrl(String chainName) {
        if (!crlInfoByChainName.containsKey(chainName)) {
            return null;
        }
        return crlInfoByChainName.get(chainName).crlHolder();
    }

    public CrlGateway.CrlHeaders getCrlHeaders(String chainName) {
        if (!crlInfoByChainName.containsKey(chainName)) {
            return null;
        }
        return crlInfoByChainName.get(chainName).crlHeaders();
    }

    public void updateCrlAndHeaders(String chainName, X509CRLHolder crlHolder, CrlGateway.CrlHeaders crlHeaders) {
        crlInfoByChainName.put(chainName, new CrlInfo(crlHeaders, crlHolder));
    }

    public record CrlInfo(CrlGateway.CrlHeaders crlHeaders, X509CRLHolder crlHolder) {
    }
}
