package ee.ria.ocspcrl.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.ocspcrl.config.CrlConfigurationProperties;
import ee.ria.ocspcrl.gateway.CrlGateway;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;

@Service
@RequiredArgsConstructor
public class FileService {

    public static final ObjectMapper jsonMapper = new ObjectMapper();

    private final FileIoService fileIoService;
    private final CrlConfigurationProperties properties;

    public void serializeToFile(String chainName, CrlGateway.NewCrlFileResponse response, FileType fileType)
            throws IOException {
        Path crlPath = getCrlTargetFilePath(chainName, fileType);
        Path headerPath = getHeadersTargetFilePath(chainName, fileType);

        fileIoService.writeToFile(crlPath, response.crl());
        serializeToFile(headerPath, response.crlCacheKey());
    }

    public <T> T deserializeFromFile(String chainName, Class<T> clazz, FileType fileType) throws IOException {
        Path filePath = null;
        if (clazz == CrlGateway.CrlCacheKey.class) {
            filePath = getHeadersTargetFilePath(chainName, fileType);
        }
        if (filePath == null) {
            return null;
        }
        return deserializeFromFile(filePath, clazz);
    }

    public boolean shouldReadHeadersFromFile(String chainName, FileType fileType) {
        boolean headersFileExists = headersFileExists(chainName, fileType);
        boolean crlFileExists = crlFileExists(chainName, fileType);

        // If there is no headers file, there are no headers to read. However, if there is
        // no CRL file, we want to load new headers and CRL so that the headers file is
        // up to date.
        return headersFileExists && crlFileExists;
    }

    private Path getCrlTargetFilePath(String chainName, FileType fileType) {
        if (fileType == FileType.TEMP) {
            return getCrlTmpTargetFilePath(chainName);
        }
        if (fileType == FileType.VALIDATED) {
            return getCrlValidatedTargetFilePath(chainName);
        }
        throw new RuntimeException("Incorrect file type " + fileType);
    }

    private Path getHeadersTargetFilePath(String chainName, FileType fileType) {
        if (fileType == FileType.TEMP) {
            return getHeadersTmpTargetFilePath(chainName);
        }
        if (fileType == FileType.VALIDATED) {
            return getHeadersValidatedTargetFilePath(chainName);
        }
        throw new RuntimeException("Incorrect file type " + fileType);
    }

    private boolean headersFileExists(String chainName, FileType fileType) {
        Path filePath = getHeadersTargetFilePath(chainName, fileType);

        return fileIoService.exists(filePath);
    }

    private boolean crlFileExists(String chainName, FileType fileType) {
        Path filePath = getCrlTargetFilePath(chainName, fileType);

        return fileIoService.exists(filePath);
    }

    private void serializeToFile(Path filePath, Object object) throws IOException {
        byte[] objectBytes = jsonMapper.writeValueAsBytes(object);

        fileIoService.writeToFile(filePath, objectBytes);
    }

    private <T> T deserializeFromFile(Path filePath, Class<T> clazz) throws IOException {
        byte[] objectBytes = fileIoService.readFromFile(filePath);

        return jsonMapper.readValue(objectBytes, clazz);
    }

    private Path getHeadersTmpTargetFilePath(String chainName) {
        String fileName = chainName + ".headers.tmp";
        return properties.tmpPath().resolve(fileName);
    }

    private Path getHeadersValidatedTargetFilePath(String chainName) {
        String fileName = chainName + ".headers";
        return properties.crlPath().resolve(fileName);
    }

    private Path getCrlTmpTargetFilePath(String chainName) {
        String fileName = chainName + ".crl.tmp";
        return properties.tmpPath().resolve(fileName);
    }

    private Path getCrlValidatedTargetFilePath(String chainName) {
        String fileName = chainName + ".crl";
        return properties.crlPath().resolve(fileName);
    }

    public enum FileType {
        TEMP, VALIDATED
    }
}
