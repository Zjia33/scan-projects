package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CodeGraphIntegrationServiceTest {

    @Test
    void returnsPagedSymbolCandidatesWithoutMappingOrSourceContent() {
        Fixture fixture = fixture();
        when(fixture.client.related(fixture.taskId,
                "OrderController.entry", 100)).thenReturn(new CodeGraphClient.RelatedLocations(
                List.of(new CodeGraphClient.CodeGraphLocation("Api.show", "method", "src/Api.java", 4)),
                List.of(new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                                "src/OrderService.java", 10),
                        new CodeGraphClient.CodeGraphLocation("OrderMapper.find", "method",
                                "src/OrderMapper.java", 6))));

        CodeGraphIntegrationService.CandidatePage first = fixture.service.relatedCandidates(
                fixture.taskId, fixture.chunks.get(0), CodeGraphIntegrationService.Direction.BOTH, 0, 2);
        CodeGraphIntegrationService.CandidatePage second = fixture.service.relatedCandidates(
                fixture.taskId, fixture.chunks.get(0), CodeGraphIntegrationService.Direction.BOTH,
                Integer.parseInt(first.nextCursor()), 2);

        assertThat(first.candidates()).hasSize(2);
        assertThat(first.truncated()).isTrue();
        assertThat(first.total()).isEqualTo(3);
        assertThat(second.candidates()).hasSize(1);
        assertThat(second.truncated()).isFalse();
        assertThat(first.candidates()).allSatisfy(candidate -> {
            assertThat(candidate.candidateId()).isNotBlank();
            assertThat(candidate.anchorChunkId()).isEqualTo(1L);
        });
    }

    @Test
    void storesCandidateForExplicitMaterializationAndMapsItStrictly() {
        Fixture fixture = fixture();
        var location = new CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "src/OrderService.java", 10);
        when(fixture.client.related(fixture.taskId,
                "OrderController.entry", 100)).thenReturn(
                new CodeGraphClient.RelatedLocations(List.of(), List.of(location)));

        var page = fixture.service.relatedCandidates(fixture.taskId, fixture.chunks.get(0),
                CodeGraphIntegrationService.Direction.CALLEES, 0, 5);
        var selected = fixture.service.candidate(fixture.taskId,
                page.candidates().get(0).candidateId());

        assertThat(selected.location()).isEqualTo(location);
        assertThat(fixture.service.mapCandidate(fixture.chunks, selected).getId()).isEqualTo(2L);
        assertThat(fixture.service.targetRoot(fixture.taskId)).isEqualTo(
                Path.of("unused-target").toAbsolutePath().normalize());
    }

    @Test
    void verifiesDirectRelationAgainstTargetIndex() {
        Fixture fixture = fixture();
        when(fixture.client.related(fixture.taskId,
                "OrderController.entry", 1000))
                .thenReturn(new CodeGraphClient.RelatedLocations(List.of(), List.of(
                        new CodeGraphClient.CodeGraphLocation("OrderService.load", "method",
                                "src/OrderService.java", 10))));

        CodeGraphIntegrationService.RelationCheck result = fixture.service.verifyDirectRelation(
                fixture.taskId, fixture.chunks.get(0), fixture.chunks.get(1), fixture.chunks);

        assertThat(result.verified()).isTrue();
        assertThat(result.reason()).contains("CodeGraph Target 索引命中");
    }

    @Test
    void refetchesWithLargerLimitWhenCliSignalsMoreRelations() {
        Fixture fixture = fixture();
        List<CodeGraphClient.CodeGraphLocation> firstHundred = java.util.stream.IntStream.range(0, 100)
                .mapToObj(index -> new CodeGraphClient.CodeGraphLocation(
                        "Caller" + index + ".entry", "method", "src/Caller" + index + ".java", 1))
                .toList();
        List<CodeGraphClient.CodeGraphLocation> all = java.util.stream.IntStream.range(0, 150)
                .mapToObj(index -> new CodeGraphClient.CodeGraphLocation(
                        "Caller" + index + ".entry", "method", "src/Caller" + index + ".java", 1))
                .toList();
        when(fixture.client.related(fixture.taskId, "OrderController.entry", 100))
                .thenReturn(new CodeGraphClient.RelatedLocations(firstHundred, List.of(), true, false));
        when(fixture.client.related(fixture.taskId, "OrderController.entry", 200))
                .thenReturn(new CodeGraphClient.RelatedLocations(all, List.of(), false, false));

        fixture.service.relatedCandidates(fixture.taskId, fixture.chunks.get(0),
                CodeGraphIntegrationService.Direction.CALLERS, 0, 10);
        CodeGraphIntegrationService.CandidatePage page = fixture.service.relatedCandidates(
                fixture.taskId, fixture.chunks.get(0), CodeGraphIntegrationService.Direction.CALLERS,
                100, 10);

        assertThat(page.candidates()).hasSize(10);
        assertThat(page.total()).isEqualTo(150);
        assertThat(page.candidates().get(0).location().name()).isEqualTo("Caller100.entry");
    }

    @Test
    void releaseClearsTaskCandidateCatalogueAndTargetRoot() {
        Fixture fixture = fixture();
        when(fixture.client.related(fixture.taskId,
                "OrderController.entry", 100)).thenReturn(new CodeGraphClient.RelatedLocations(
                List.of(), List.of(new CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "src/OrderService.java", 10))));
        var page = fixture.service.relatedCandidates(fixture.taskId, fixture.chunks.get(0),
                CodeGraphIntegrationService.Direction.CALLEES, 0, 5);
        String candidateId = page.candidates().get(0).candidateId();

        fixture.service.release(fixture.taskId);

        assertThat(fixture.service.candidate(fixture.taskId, candidateId)).isNull();
        assertThat(fixture.service.targetRoot(fixture.taskId)).isNull();
    }

    private Fixture fixture() {
        UUID taskId = UUID.randomUUID();
        CodeChunk changed = chunk(taskId, 1L, "src/OrderController.java", "OrderController#entry", 1, 8);
        CodeChunk external = chunk(taskId, 2L, "src/OrderService.java", "OrderService#load", 10, 20);
        List<CodeChunk> chunks = List.of(changed, external);
        CodeGraphClient client = mock(CodeGraphClient.class);
        CodeGraphIntegrationService service = new CodeGraphIntegrationService(
                new CodeGraphProperties(), client, new CodeGraphResultMapper());
        service.prepare(taskId, Path.of("unused-target"));
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
