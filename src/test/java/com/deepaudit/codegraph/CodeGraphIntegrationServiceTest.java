package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CodeGraphIntegrationServiceTest {
    @Test
    void shadowModeMeasuresButDoesNotChangeNativeImpactScope() {
        Fixture fixture = fixture(CodeGraphMode.SHADOW);

        CodeGraphIntegrationService.ImpactDecision result = fixture.service.decideImpact(
                fixture.taskId, fixture.chunks, Set.of(1L), Set.of(3L));

        assertThat(result.codeGraphImpactedChunkIds()).containsExactly(2L);
        assertThat(result.effectiveImpactedChunkIds()).containsExactly(3L);
    }

    @Test
    void augmentModeUnionsCodeGraphAndNativeImpactWithoutRemovingNativeTargets() {
        Fixture fixture = fixture(CodeGraphMode.AUGMENT);

        CodeGraphIntegrationService.ImpactDecision result = fixture.service.decideImpact(
                fixture.taskId, fixture.chunks, Set.of(1L), Set.of(3L));

        assertThat(result.effectiveImpactedChunkIds()).containsExactlyInAnyOrder(2L, 3L);
    }

    @Test
    void agentContextReturnsOnlyCandidateChunkIdsInAugmentMode() {
        Fixture fixture = fixture(CodeGraphMode.AUGMENT);
        when(fixture.client.related(fixture.taskId, "OrderController.entry", 10))
                .thenReturn(new CodeGraphClient.RelatedLocations(List.of(
                        new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                                "src/OrderService.java", 10)), List.of()));

        CodeGraphIntegrationService.CandidateContext result = fixture.service.candidateContext(
                fixture.taskId, fixture.chunks.get(0), fixture.chunks, 10);

        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("CODEGRAPH_CANDIDATE", "verify_relation", "CHUNK_ID=2");
    }

    private Fixture fixture(CodeGraphMode mode) {
        UUID taskId = UUID.randomUUID();
        CodeChunk changed = chunk(taskId, 1L, "src/OrderController.java", "OrderController#entry", 1, 8);
        CodeChunk external = chunk(taskId, 2L, "src/OrderService.java", "OrderService#load", 10, 20);
        CodeChunk nativeImpact = chunk(taskId, 3L, "src/OrderRepository.java", "OrderRepository#find", 4, 7);
        List<CodeChunk> chunks = List.of(changed, external, nativeImpact);
        CodeGraphProperties properties = new CodeGraphProperties();
        properties.setMode(mode);
        CodeGraphClient client = mock(CodeGraphClient.class);
        when(client.impact(taskId, "OrderController.entry", 2)).thenReturn(List.of(
                new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                        "src/OrderService.java", 10)));
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused"));
        return new Fixture(taskId, chunks, client, service);
    }

    private CodeChunk chunk(UUID taskId, long id, String path, String symbol, int start, int end) {
        CodeChunk chunk = new CodeChunk(taskId, path, symbol, null,
                start, end, "method", "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        return chunk;
    }

    private record Fixture(UUID taskId, List<CodeChunk> chunks,
                           CodeGraphClient client, CodeGraphIntegrationService service) {
    }
}
