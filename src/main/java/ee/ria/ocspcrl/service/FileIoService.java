package ee.ria.ocspcrl.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@Slf4j
@Service
public class FileIoService {

    public void writeToFile(Path filePath, byte[] content) throws IOException {
        Files.createDirectories(filePath.getParent());
        Files.write(filePath, content);
    }

    public byte[] readFromFile(Path filePath) throws IOException {
        return Files.readAllBytes(filePath);
    }

    public boolean exists(Path filePath) {
        return Files.exists(filePath);
    }

    public void move(Path source, Path target) throws IOException {
        Files.createDirectories(target.getParent());

        CopyOption[] copyOptions = {
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
        };

        Files.move(source, target, copyOptions);
    }
}
