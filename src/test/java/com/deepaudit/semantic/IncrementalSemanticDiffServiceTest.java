package com.deepaudit.semantic;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class IncrementalSemanticDiffServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void indexesBothSnapshotsAndClassifiesDeletionSignatureAndGuardChanges() throws Exception {
        Path base = temporaryDirectory.resolve("base");
        Path target = temporaryDirectory.resolve("target");
        String path = "src/main/java/demo/OrderService.java";
        write(base, path, """
                package demo;
                class OrderService {
                    Object find(Long id) {
                        checkOwner(id);
                        return repository.findById(id);
                    }
                    void update(Long id) {}
                    void removeLegacy() {}
                }
                """);
        write(target, path, """
                package demo;
                class OrderService {
                    Object find(Long id) {
                        return repository.findById(id);
                    }
                    @PreAuthorize("hasRole('ADMIN')")
                    void update(Long id, String name) {}
                    void created() {}
                }
                """);

        UUID taskId = UUID.randomUUID();
        List<CodeChunk> chunks = List.of(
                chunk(taskId, path, "OrderService#find", 3, 5),
                chunk(taskId, path, "OrderService#update", 6, 7),
                chunk(taskId, path, "OrderService#created", 8, 8));
        GitFileChange fileChange = new GitFileChange(taskId, path, path, "MODIFY",
                3, 3, "4:8", "4:8", "", false);
        SemanticMethodChangeMapper mapper = mock(SemanticMethodChangeMapper.class);

        IncrementalSemanticDiffService.Summary summary = new IncrementalSemanticDiffService(mapper)
                .analyze(taskId, base, target, chunks, List.of(fileChange));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<SemanticMethodChange>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        List<SemanticMethodChange> changes = captor.getValue();
        assertThat(changes).extracting(SemanticMethodChange::getChangeKind)
                .contains(SemanticChangeKind.METHOD_ADDED, SemanticChangeKind.METHOD_MODIFIED,
                        SemanticChangeKind.METHOD_DELETED, SemanticChangeKind.SIGNATURE_CHANGED,
                        SemanticChangeKind.GUARD_ADDED, SemanticChangeKind.GUARD_REMOVED);
        assertThat(summary.baseMethodCount()).isEqualTo(3);
        assertThat(summary.targetMethodCount()).isEqualTo(3);
        assertThat(chunks.get(0).getAnalysisScope()).isEqualTo(AnalysisScope.CHANGED);
        assertThat(chunks.get(0).getBaseContent()).contains("checkOwner(id)");
        assertThat(changes).filteredOn(change -> change.getChangeKind() == SemanticChangeKind.GUARD_REMOVED)
                .singleElement().satisfies(change -> assertThat(change.getDetails()).contains("checkOwner"));
    }

    private CodeChunk chunk(UUID taskId, String path, String symbol, int start, int end) {
        return new CodeChunk(taskId, path, symbol, null, start, end, "method", "",
                "JAVA_METHOD", "", "", "");
    }

    private void write(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
