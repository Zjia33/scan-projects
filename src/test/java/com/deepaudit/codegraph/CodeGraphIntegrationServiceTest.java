package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
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
    void queriesSymbolsOnlyAgainstPreparedTargetIndex() {
        UUID taskId = UUID.randomUUID();
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphClient client = mock(CodeGraphClient.class);
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        Path targetRoot = Path.of("unused-target");
        service.prepare(taskId, Path.of("unused-base"), targetRoot);
        when(client.query(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", "method", 100))
                .thenReturn(List.of(new CodeGraphClient.CodeGraphLocation(
                        "OrderService.load", "method", "src/OrderService.java", 7)));

        CodeGraphIntegrationService.SymbolQueryResult result = service.querySymbols(
                taskId, "OrderService#load", "method", 100);

        assertThat(result.attempted()).isTrue();
        assertThat(result.failed()).isFalse();
        assertThat(result.locations()).singleElement()
                .extracting(CodeGraphClient.CodeGraphLocation::filePath)
                .isEqualTo("src/OrderService.java");
        assertThat(result.targetRoot()).isEqualTo(targetRoot.toAbsolutePath().normalize());
    }

    @Test
    void unionsCodeGraphAndDeterministicImpactWithoutRemovingNativeTargets() {
        Fixture fixture = fixture();

        CodeGraphIntegrationService.ImpactDecision result = fixture.service.decideImpact(
                fixture.taskId, fixture.chunks, Set.of(1L), Set.of(3L), List.of());

        assertThat(result.effectiveImpactedChunkIds()).containsExactlyInAnyOrder(2L, 3L);
    }

    @Test
    void agentContextReturnsUnverifiedDirectRelationCandidates() {
        Fixture fixture = fixture();
        when(fixture.client.callers(fixture.taskId, CodeGraphSnapshot.TARGET,
                "OrderController.entry", 10)).thenReturn(List.of(
                new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                        "src/OrderService.java", 10)));
        when(fixture.client.callees(fixture.taskId, CodeGraphSnapshot.TARGET,
                "OrderController.entry", 10)).thenReturn(List.of());

        CodeGraphIntegrationService.RelationContext result = fixture.service.relationContext(
                fixture.taskId, fixture.chunks.get(0), fixture.chunks, 10);

        assertThat(result.relatedChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("UNVERIFIED_CANDIDATE", "CODEGRAPH_RELATIONS", "CHUNK_ID=2");
    }

    @Test
    void deletionUsesBaseCallersAndMapsSurvivingCallerIntoTargetScope() {
        UUID taskId = UUID.randomUUID();
        CodeChunk caller = chunk(taskId, 1L, "src/OrderController.java", "OrderController#load", 5, 15);
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphClient client = mock(CodeGraphClient.class);
        when(client.impact(taskId, CodeGraphSnapshot.BASE, "demo.OrderService.removed", 2))
                .thenReturn(List.of());
        when(client.callers(taskId, CodeGraphSnapshot.BASE, "demo.OrderService.removed", 100))
                .thenReturn(List.of(new CodeGraphClient.CodeGraphLocation(
                        "OrderController.load", "method", "src/OrderController.java", 7)));
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused-base"), Path.of("unused-target"));
        SemanticMethodChange deleted = new SemanticMethodChange(taskId, SemanticChangeKind.METHOD_DELETED,
                "removed", "src/OrderService.java", null, "demo.OrderService.removed()", null,
                4, 8, null, null, "void removed() {}", "", "方法已删除");

        CodeGraphIntegrationService.ImpactDecision result = service.decideImpact(
                taskId, List.of(caller), Set.of(), Set.of(), List.of(deleted));

        assertThat(result.effectiveImpactedChunkIds()).containsExactly(1L);
    }

    @Test
    void buildsDirectedScopedTopologyFromTargetCallersAndCallees() {
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(taskId, 1L, "src/OrderService.java", "OrderService#load", 10, 20);
        CodeChunk caller = chunk(taskId, 2L, "src/OrderController.java", "OrderController#show", 4, 9);
        CodeChunk callee = chunk(taskId, 3L, "src/OrderMapper.java", "OrderMapper#find", 2, 7);
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphClient client = mock(CodeGraphClient.class);
        when(client.callers(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 100))
                .thenReturn(List.of(new CodeGraphClient.CodeGraphLocation(
                        "OrderController.show", "method", "src/OrderController.java", 6)));
        when(client.callees(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 100))
                .thenReturn(List.of(new CodeGraphClient.CodeGraphLocation(
                        "OrderMapper.find", "method", "src/OrderMapper.java", 4)));
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused-base"), Path.of("unused-target"));

        CodeGraphIntegrationService.ScopedTopology topology = service.scopedTopology(
                taskId, List.of(current, caller, callee), Set.of(1L));

        assertThat(topology.contextChunkIds()).containsExactlyInAnyOrder(2L, 3L);
        assertThat(topology.relations()).extracting(
                CodeGraphIntegrationService.ScopedRelation::callerChunkId,
                CodeGraphIntegrationService.ScopedRelation::calleeChunkId)
                .containsExactlyInAnyOrder(org.assertj.core.groups.Tuple.tuple(2L, 1L),
                        org.assertj.core.groups.Tuple.tuple(1L, 3L));
    }

    @Test
    void keepsSuccessfulScopedRelationsAndContinuesWhenOneDirectionFails() {
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(taskId, 1L, "src/OrderService.java", "OrderService#load", 10, 20);
        CodeChunk caller = chunk(taskId, 2L, "src/OrderController.java", "OrderController#show", 4, 9);
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphClient client = mock(CodeGraphClient.class);
        when(client.callers(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 100))
                .thenReturn(List.of(new CodeGraphClient.CodeGraphLocation(
                        "OrderController.show", "method", "src/OrderController.java", 6)));
        when(client.callees(taskId, CodeGraphSnapshot.TARGET, "OrderService.load", 100))
                .thenThrow(new CodeGraphException("callees command timed out"));
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused-base"), Path.of("unused-target"));

        CodeGraphIntegrationService.ScopedTopology topology = service.scopedTopology(
                taskId, List.of(current, caller), Set.of(1L));

        assertThat(topology.failedQueries()).isEqualTo(1);
        assertThat(topology.contextChunkIds()).containsExactly(2L);
        assertThat(topology.relations()).singleElement().satisfies(relation -> {
            assertThat(relation.callerChunkId()).isEqualTo(2L);
            assertThat(relation.calleeChunkId()).isEqualTo(1L);
        });
    }

    @Test
    void keepsDirectCodeGraphRelationAsCandidateWithoutLocalCallSiteProof() {
        Fixture fixture = fixture();
        when(fixture.client.callers(fixture.taskId, CodeGraphSnapshot.TARGET,
                "OrderController.entry", 100)).thenReturn(List.of());
        when(fixture.client.callees(fixture.taskId, CodeGraphSnapshot.TARGET,
                "OrderController.entry", 100)).thenReturn(List.of(
                new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                        "src/OrderService.java", 10)));

        CodeGraphIntegrationService.RelationCheck result = fixture.service.verifyDirectRelation(
                fixture.taskId, fixture.chunks.get(0), fixture.chunks.get(1), fixture.chunks);

        assertThat(result.verified()).isFalse();
        assertThat(result.reason()).contains("本地调用点验证");
    }

    private Fixture fixture() {
        UUID taskId = UUID.randomUUID();
        CodeChunk changed = chunk(taskId, 1L, "src/OrderController.java", "OrderController#entry", 1, 8);
        CodeChunk external = chunk(taskId, 2L, "src/OrderService.java", "OrderService#load", 10, 20);
        CodeChunk nativeImpact = chunk(taskId, 3L, "src/OrderRepository.java", "OrderRepository#find", 4, 7);
        List<CodeChunk> chunks = List.of(changed, external, nativeImpact);
        CodeGraphProperties properties = new CodeGraphProperties();
        CodeGraphClient client = mock(CodeGraphClient.class);
        when(client.impact(taskId, CodeGraphSnapshot.TARGET, "OrderController.entry", 2)).thenReturn(List.of(
                new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                        "src/OrderService.java", 10)));
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                properties, client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused-base"), Path.of("unused-target"));
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
