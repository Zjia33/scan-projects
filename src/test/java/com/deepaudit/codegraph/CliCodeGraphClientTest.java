package com.deepaudit.codegraph;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

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
    void queriesTargetSymbolsWithKindAndJsonOutput() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""),
                output(0, "[{\"node\":{\"name\":\"OrderService.load\",\"kind\":\"method\","
                        + "\"filePath\":\"src/OrderService.java\",\"startLine\":7}}]", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        target.prepare(taskId, CodeGraphSnapshot.TARGET, root);
        List<CodeGraphClient.CodeGraphLocation> result = target.query(
                taskId, CodeGraphSnapshot.TARGET, "OrderService#load", "method", 20);

        assertThat(result).singleElement().satisfies(location -> {
            assertThat(location.name()).isEqualTo("OrderService.load");
            assertThat(location.filePath()).isEqualTo("src/OrderService.java");
            assertThat(location.startLine()).isEqualTo(7);
        });
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> arguments = ArgumentCaptor.forClass(List.class);
        verify(runner, times(3)).run(eq(root.toRealPath()), arguments.capture(), anyMap());
        assertThat(arguments.getAllValues().get(2)).containsExactly(
                "query", "OrderService#load", "--path", root.toRealPath().toString(),
                "--kind", "method", "--limit", "20", "--json", "--no-color");
    }

    @Test
    void executesCallersAndCalleesAsIndependentCommands() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""),
                output(0, "{\"callers\":[]}", ""),
                output(0, "{\"callees\":[]}", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(
                new CodeGraphProperties(), runner, new ObjectMapper());

        target.prepare(taskId, CodeGraphSnapshot.TARGET, root);
        target.callers(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 7);
        target.callees(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 9);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> arguments = ArgumentCaptor.forClass(List.class);
        verify(runner, times(4)).run(eq(root.toRealPath()), arguments.capture(), anyMap());
        assertThat(arguments.getAllValues().get(2)).containsExactly(
                "callers", "OrderService.load", "--path", root.toRealPath().toString(),
                "--limit", "7", "--json", "--no-color");
        assertThat(arguments.getAllValues().get(3)).containsExactly(
                "callees", "OrderService.load", "--path", root.toRealPath().toString(),
                "--limit", "9", "--json", "--no-color");
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
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        target.prepare(taskId, CodeGraphSnapshot.TARGET, root);

        verify(runner, times(2)).run(eq(root.toRealPath()), anyList(), anyMap());
        assertThatThrownBy(() -> target.impact(UUID.randomUUID(), CodeGraphSnapshot.TARGET,
                "OrderService.load", 2))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("尚未建立");
    }

    @Test
    void rejectsAnExplicitlyIncompleteIndex() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"partial\"}}", ""));
        CliCodeGraphClient target = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        assertThatThrownBy(() -> target.prepare(taskId, CodeGraphSnapshot.TARGET, root))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("索引不完整");
    }

    @Test
    void rejectsUnsafeIndexDirectoryBeforeStartingTheCli() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path root = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setIndexDirectory("../outside");
        CliCodeGraphClient target = new CliCodeGraphClient(
                properties, mock(CodeGraphCommandRunner.class), new ObjectMapper());

        assertThatThrownBy(() -> target.prepare(taskId, CodeGraphSnapshot.TARGET, root))
                .isInstanceOf(CodeGraphException.class)
                .hasMessageContaining("单级相对目录名");
    }

    @Test
    void preparesBaseAndTargetAsIndependentIndexes() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path base = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-base"));
        Path target = Files.createDirectory(temporaryDirectory.resolve("workspace-" + taskId + "-target"));
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(org.mockito.ArgumentMatchers.any(Path.class), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""),
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""));
        CliCodeGraphClient dual = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        dual.prepare(taskId, CodeGraphSnapshot.BASE, base);
        dual.prepare(taskId, CodeGraphSnapshot.TARGET, target);

        verify(runner, times(2)).run(eq(base.toRealPath()), anyList(), anyMap());
        verify(runner, times(2)).run(eq(target.toRealPath()), anyList(), anyMap());
    }

    @Test
    void acceptsACommitScopedCacheWorkspace() throws Exception {
        UUID taskId = UUID.randomUUID();
        Path cache = Files.createDirectory(temporaryDirectory.resolve("commit-cache"));
        Path root = Files.createDirectory(cache.resolve("0123456789abcdef0123456789abcdef01234567"));
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphCommandRunner runner = mock(CodeGraphCommandRunner.class);
        when(runner.run(eq(root.toRealPath()), anyList(), anyMap())).thenReturn(
                output(0, "", ""),
                output(0, "{\"initialized\":true,\"index\":{\"state\":\"complete\",\"pendingRefs\":0}}", ""));
        CliCodeGraphClient cached = new CliCodeGraphClient(properties, runner, new ObjectMapper());

        cached.prepare(taskId, CodeGraphSnapshot.TARGET, root);

        verify(runner, times(2)).run(eq(root.toRealPath()), anyList(), anyMap());
    }

    private CodeGraphCommandRunner.CommandOutput output(int exitCode, String stdout, String stderr) {
        return new CodeGraphCommandRunner.CommandOutput(exitCode, stdout, stderr, Duration.ZERO);
    }
}
