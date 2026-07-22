package com.deepaudit.storage;

import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Component
public class SafeZipExtractor {

    static final int MAX_FILES = 50_000;
    static final long MAX_TOTAL_BYTES = 1024L * 1024L * 1024L;
    static final long MAX_SINGLE_FILE_BYTES = 10L * 1024L * 1024L;
    private static final Set<String> SKIPPED_DIRECTORIES = Set.of(".git", ".idea", "target", "build", "node_modules");

    // 在文件数、大小和路径边界约束下将 ZIP 解压到隔离目录。
    public ExtractionResult extract(Path zipFile, Path destination) throws IOException {
        Path normalizedDestination = destination.toAbsolutePath().normalize();
        Files.createDirectories(normalizedDestination);
        int fileCount = 0;
        long totalBytes = 0;

        try (InputStream input = new BufferedInputStream(Files.newInputStream(zipFile));
             ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];
            while ((entry = zip.getNextEntry()) != null) {
                // 统一分隔符并跳过依赖、构建产物和嵌套压缩包。
                String entryName = entry.getName().replace('\\', '/');
                if (entryName.isBlank() || shouldSkip(entryName)) {
                    zip.closeEntry();
                    continue;
                }
                // 规范化每个输出路径以阻断 Zip Slip 越界写入。
                Path output = normalizedDestination.resolve(entryName).normalize();
                if (!output.startsWith(normalizedDestination)) {
                    throw new IOException("ZIP 包含越界路径: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(output);
                    zip.closeEntry();
                    continue;
                }
                if (++fileCount > MAX_FILES) {
                    throw new IOException("ZIP 文件数量超过限制: " + MAX_FILES);
                }
                // 流式写入并同时限制单文件及总解压体积，防止压缩炸弹。
                Files.createDirectories(output.getParent());
                long fileBytes = 0;
                try (OutputStream target = new BufferedOutputStream(Files.newOutputStream(output,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
                    int read;
                    while ((read = zip.read(buffer)) >= 0) {
                        if (read == 0) continue;
                        fileBytes += read;
                        totalBytes += read;
                        if (fileBytes > MAX_SINGLE_FILE_BYTES) {
                            throw new IOException("单文件解压后超过限制: " + entry.getName());
                        }
                        if (totalBytes > MAX_TOTAL_BYTES) {
                            throw new IOException("ZIP 解压总大小超过限制");
                        }
                        target.write(buffer, 0, read);
                    }
                }
                zip.closeEntry();
            }
        }
        return new ExtractionResult(fileCount, totalBytes, normalizedDestination);
    }

    // 排除无需审计且容易显著放大扫描体积的归档内容。
    private boolean shouldSkip(String entryName) {
        String[] parts = entryName.split("/");
        for (String part : parts) {
            if (SKIPPED_DIRECTORIES.contains(part)) return true;
        }
        String normalized = entryName.toLowerCase(Locale.ROOT);
        return normalized.endsWith(".zip") || normalized.endsWith(".jar") || normalized.endsWith(".war");
    }

    public record ExtractionResult(int fileCount, long totalBytes, Path destination) {
    }
}
