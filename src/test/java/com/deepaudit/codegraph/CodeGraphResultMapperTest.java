package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CodeGraphResultMapperTest {
    private final CodeGraphResultMapper mapper = new CodeGraphResultMapper();

    @Test
    void mapsLocationsByNormalizedPathLineAndSymbol() {
        CodeChunk first = chunk(1L, "src/main/java/demo/OrderService.java", "OrderService#load", 10, 20);
        CodeChunk second = chunk(2L, "src/main/java/demo/OrderService.java", "OrderService#save", 24, 35);

        CodeGraphResultMapper.MappingResult result = mapper.map(List.of(first, second), List.of(
                new CodeGraphClient.CodeGraphLocation("demo.OrderService.save", "method",
                        ".\\src\\main\\java\\demo\\OrderService.java", 27),
                new CodeGraphClient.CodeGraphLocation("missing", "method", "src/Missing.java", 1)));

        assertThat(result.chunkIds()).containsExactly(2L);
        assertThat(result.unmappedLocations()).isEqualTo(1);
    }

    @Test
    void doesNotGuessWhenSeveralChunksHaveNeitherLineNorMatchingName() {
        CodeChunk first = chunk(1L, "demo/Service.java", "Service#first", 1, 5);
        CodeChunk second = chunk(2L, "demo/Service.java", "Service#second", 8, 12);

        CodeGraphResultMapper.MappingResult result = mapper.map(List.of(first, second), List.of(
                new CodeGraphClient.CodeGraphLocation("unknown", "method", "demo/Service.java", null)));

        assertThat(result.chunkIds()).isEmpty();
        assertThat(result.unmappedLocations()).isEqualTo(1);
    }

    @Test
    void mapsAnAbsoluteCodeGraphPathOnlyWhenItsProjectRelativeSuffixIsUnique() {
        CodeChunk chunk = chunk(7L, "src/main/java/demo/OrderService.java", "OrderService#load", 10, 20);

        CodeGraphResultMapper.MappingResult result = mapper.map(List.of(chunk), List.of(
                new CodeGraphClient.CodeGraphLocation("demo.OrderService.load", "method",
                        "C:/temp/workspace/src/main/java/demo/OrderService.java", 12)));

        assertThat(result.chunkIds()).containsExactly(7L);
    }

    @Test
    void doesNotGuessBetweenOverloadedSymbolsWithoutALine() {
        CodeChunk first = chunk(1L, "demo/Service.java", "Service#load(String)", 1, 5);
        CodeChunk second = chunk(2L, "demo/Service.java", "Service#load(Long)", 8, 12);

        CodeGraphResultMapper.MappingResult result = mapper.map(List.of(first, second), List.of(
                new CodeGraphClient.CodeGraphLocation("Service.load", "method", "demo/Service.java", null)));

        assertThat(result.chunkIds()).isEmpty();
        assertThat(result.unmappedLocations()).isEqualTo(1);
    }

    private CodeChunk chunk(long id, String path, String symbol, int start, int end) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), path, symbol, null,
                start, end, "method", "", "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        return chunk;
    }
}
