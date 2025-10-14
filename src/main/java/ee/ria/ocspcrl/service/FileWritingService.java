package ee.ria.ocspcrl.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
@Service
public class FileWritingService {

    public void writeToFile(Path filePath, byte[] content) throws IOException {
        Files.createDirectories(filePath.getParent());
        Files.write(filePath, content);
    }
}
