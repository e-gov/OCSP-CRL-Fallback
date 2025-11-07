package ee.ria.ocspcrl.gateway;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.restclient.autoconfigure.RestClientSsl;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CrlGatewayFactory {

    private final RestClientSsl restClientSsl;

    //TODO AUT-2429 Cache gateways
    public CrlGateway create(CrlConfigurationProperties.CrlDownload crlDownload) {
        return new CrlGateway(crlDownload, restClientSsl);
    }

}
