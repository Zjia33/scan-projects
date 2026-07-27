package com.deepaudit.codegraph;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CliCodeGraphClientTest {
    private final CliCodeGraphClient client = new CliCodeGraphClient(
            new CodeGraphProperties(), mock(CodeGraphCommandRunner.class), new ObjectMapper());

    @TempDir
    Path temporaryDirectory;

    @Test
    void parsesImpactAndRelationJsonShapes() {
        List<CodeGraphClient.CodeGraphLocation> impact = client.parseLocations("""
                {"symbol":"OrderService.load","affected":[
                  {"name":"OrderController.show","kind":"method","filePath":"src\\\\OrderController.java","startLine":18}
                ]}
                """, "affected");
        List<CodeGraphClient.CodeGraphLocation> query = client.parseLocations("""
                [{"node":{"name":"OrderService.load","kind":"method","filePath":"src/OrderService.java","startLine":7},"score":1.0}]
                """, "query");

        assertThat(impact).singleElement().satisfies(location -> {
            assertThat(location.filePath()).isEqualTo("src/OrderController.java");
            assertThat(location.startLine()).isEqualTo(18);
        });
        assertThat(query).singleElement().extracting(CodeGraphClient.CodeGraphLocation::name)
                .isEqualTo("OrderService.load");
    }

    @Test
    void treatsNoMatchMessageAsEmptyResult() {
        assertThat(client.parseLocations("Symbol not found", "affected")).isEmpty();
    }

    @Test
    void preparesOnlyACompleteTaskTargetSnapshot() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setMode(CodeGraphMode.SHADOW);
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        target.prepare(taskId, root);

        verify(runner, times(2)).run(eq(root.toRealPath()), anyList(), anyMap());
        assertThatThrownBy(() -> target.impact(UUID.randomUUID(), "OrderService.load", 2))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("尚未建立");
    }

    @Test
    void rejectsAnExplicitlyIncompleteIndex() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setMode(CodeGraphMode.SHADOW);
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"partial\"}}", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        assertThatThrownBy(() -> target.prepare(taskId, root))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("索引不完整");
    }

    @Test
    void rejectsUnsafeIndexDirectoryBeforeStartingTheCli() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setMode(CodeGraphMode.SHADOW);
        properties.setIndexDirectory("../outside");
        CliCodeGraphClient target = new CliCodeGraphClient(
                properties, mock(CodeGraphCommandRunner.class), new ObjectMapper());

        assertThatThrownBy(() -> target.prepare(taskId, root))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("单级相对目录名");
    }

    private CodeGraphCommandRunner.CommandOutput output(int exitCode, String stdout, String stderr) {
        return new CodeGraphCommandRunner.CommandOutput(exitCode, stdout, stderr, Duration.ZERO);
    }
}
