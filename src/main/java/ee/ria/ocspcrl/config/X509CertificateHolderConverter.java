package ee.ria.ocspcrl.config;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.lang.Contract;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;

@Component
@ConfigurationPropertiesBinding
@RequiredArgsConstructor
public class X509CertificateHolderConverter implements Converter<String, X509CertificateHolder> {

    private final ResourceLoader resourceLoader;

    @Override
    @Contract("null -> null; !null -> !null")
    public @Nullable X509CertificateHolder convert(@Nullable String source) {
        if (source == null) {
            return null;
        }
        Resource resource = resourceLoader.getResource(source);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(resource.getInputStream()))) {
            Object parsedObject = pemParser.readObject();
            if (!(parsedObject instanceof X509CertificateHolder certificate)) {
                throw new IllegalArgumentException("Resource is not an X.509 certificate");
            }
            return certificate;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
