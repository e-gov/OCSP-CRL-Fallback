package ee.ria.ocspcrl.config.oscp;

import lombok.NonNull;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

import java.io.IOException;
import java.io.InputStream;

@Component
public class OcspReqHttpMessageConverter extends AbstractHttpMessageConverter<OCSPReq> {

    public static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    static final DataSize MAX_BODY_SIZE = DataSize.ofKilobytes(10);

    public OcspReqHttpMessageConverter() {
        super(MediaType.valueOf(OCSP_REQUEST_CONTENT_TYPE));
    }

    @Override
    protected boolean supports(@NonNull Class<?> clazz) {
        return OCSPReq.class.isAssignableFrom(clazz);
    }

    @Override
    @NonNull
    protected OCSPReq readInternal(@NonNull Class<? extends OCSPReq> clazz, @NonNull HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        try (InputStream requestBodyStream = inputMessage.getBody()) {
            byte[] bytes = requestBodyStream.readNBytes(Math.toIntExact(MAX_BODY_SIZE.toBytes()));
            if (requestBodyStream.read() != -1) {
                throw new HttpMessageNotReadableException(
                        "Expected OCSP request to be no larger than " + MAX_BODY_SIZE, inputMessage);
            }
            return new OCSPReq(bytes);
        }
    }

    @Override
    protected void writeInternal(@NonNull OCSPReq ocspReq, @NonNull HttpOutputMessage outputMessage)
            throws HttpMessageNotWritableException {
        throw new HttpMessageNotWritableException("Serializing OCSP requests is not implemented");
    }

}
