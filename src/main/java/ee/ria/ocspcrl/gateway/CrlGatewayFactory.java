package ee.ria.ocspcrl.gateway;

import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
@RequiredArgsConstructor
public class CrlGatewayFactory {

    private final CrlRestClientFactory crlRestClientFactory;

    //TODO AUT-2429 Cache gateways
    public CrlGateway create(CrlConfigurationProperties.CrlDownload crlDownload) {
        RestClient restClient = crlRestClientFactory.create(crlDownload);
        return new CrlGateway(restClient);
    }

}
