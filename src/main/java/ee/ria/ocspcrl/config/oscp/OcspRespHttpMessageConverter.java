package ee.ria.ocspcrl.config.oscp;

import lombok.NonNull;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

@Component
public class OcspRespHttpMessageConverter extends AbstractHttpMessageConverter<OCSPResp> {

    public static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    public OcspRespHttpMessageConverter() {
        super(MediaType.valueOf(OCSP_RESPONSE_CONTENT_TYPE));
    }

    @Override
    protected boolean supports(@NonNull Class<?> clazz) {
        return OCSPResp.class.isAssignableFrom(clazz);
    }

    @Override
    @NonNull
    protected OCSPResp readInternal(@NonNull Class<? extends OCSPResp> clazz, @NonNull HttpInputMessage inputMessage)
            throws HttpMessageNotReadableException {
        throw new HttpMessageNotReadableException("Deserializing OCSP responses is not implemented", inputMessage);
    }

    @Override
    protected void writeInternal(@NonNull OCSPResp ocspResp, @NonNull HttpOutputMessage outputMessage)
            throws IOException, HttpMessageNotWritableException {
        byte[] encoded;
        try {
            encoded = ocspResp.getEncoded();
        } catch (IOException e) {
            throw new HttpMessageNotWritableException("Failed to encode OCSP response", e);
        }
        try(OutputStream responseBodyStream = outputMessage.getBody()) {
            responseBodyStream.write(encoded);
        }
    }

}
