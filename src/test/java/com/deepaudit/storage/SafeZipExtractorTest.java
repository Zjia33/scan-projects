package com.deepaudit.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafeZipExtractorTest {

    @TempDir
    Path tempDirectory;

    private final SafeZipExtractor extractor = new SafeZipExtractor();

    @Test
    void extractsSourceAndSkipsBuildArtifactsAndNestedArchives() throws Exception {
        Path zip = writeZip(Map.of(
                "demo/src/main/java/App.java", "class App {}",
                "demo/target/App.class", "binary",
                "demo/vendor.zip", "nested"
        ));

        SafeZipExtractor.ExtractionResult result = extractor.extract(zip, tempDirectory.resolve("out"));

        assertThat(result.fileCount()).isEqualTo(1);
        assertThat(result.destination().resolve("demo/src/main/java/App.java")).hasContent("class App {}");
        assertThat(result.destination().resolve("demo/target/App.class")).doesNotExist();
        assertThat(result.destination().resolve("demo/vendor.zip")).doesNotExist();
    }

    @Test
    void rejectsZipSlipEntry() throws Exception {
        Path zip = writeZip(Map.of("../../outside.txt", "escaped"));

        assertThatThrownBy(() -> extractor.extract(zip, tempDirectory.resolve("safe")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("越界路径");
        assertThat(tempDirectory.resolve("outside.txt")).doesNotExist();
    }

    private Path writeZip(Map<String, String> entries) throws IOException {
        Path zip = tempDirectory.resolve("sample-" + System.nanoTime() + ".zip");
        Map<String, String> ordered = new LinkedHashMap<>(entries);
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(zip))) {
            for (Map.Entry<String, String> entry : ordered.entrySet()) {
                output.putNextEntry(new ZipEntry(entry.getKey()));
                output.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                output.closeEntry();
            }
        }
        return zip;
    }
}
