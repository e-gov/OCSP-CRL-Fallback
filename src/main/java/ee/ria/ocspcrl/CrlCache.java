package ee.ria.ocspcrl;

import ee.ria.ocspcrl.gateway.CrlGateway;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
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
        return crlInfoByChainName.get(chainName).getCrlHolder();
    }

    public CrlGateway.CrlHeaders getCrlHeaders(String chainName) {
        if (!crlInfoByChainName.containsKey(chainName)) {
            return null;
        }
        return crlInfoByChainName.get(chainName).getCrlHeaders();
    }

    public void updateCrlAndHeaders(String chainName, X509CRLHolder crlHolder, CrlGateway.CrlHeaders crlHeaders) {
        crlInfoByChainName.compute(chainName, (k, crlInfo) -> {
            if (crlInfo == null) {
                crlInfo = new CrlInfo();
            }
            crlInfo.setCrlHolder(crlHolder);
            crlInfo.setCrlHeaders(crlHeaders);
            return crlInfo;
        });
    }

    @Getter
    @Setter
    @RequiredArgsConstructor
    @AllArgsConstructor
    public static class CrlInfo {
        private CrlGateway.CrlHeaders crlHeaders;
        private X509CRLHolder crlHolder;
    }
}
