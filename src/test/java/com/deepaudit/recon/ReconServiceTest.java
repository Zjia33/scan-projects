package com.deepaudit.recon;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.rag.EmbeddingService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ReconServiceTest {

    @TempDir
    Path projectRoot;

    @Test
    void indexesLargeTemplateAsBoundedLineAwareChunks() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        EmbeddingService embeddings = mock(EmbeddingService.class);
        when(embeddings.embedAll(anyList())).thenAnswer(invocation -> {
            List<String> inputs = invocation.getArgument(0);
            List<double[]> vectors = new ArrayList<>();
            inputs.forEach(ignored -> vectors.add(new double[]{1, 0}));
            return vectors;
        });
        when(embeddings.serialize(org.mockito.ArgumentMatchers.any(double[].class))).thenReturn("1,0");

        List<String> lines = new ArrayList<>();
        for (int line = 1; line <= 220; line++) {
            lines.add(line == 190 ? "<div v-html=\"comment.content\"></div>" : "<p>line-" + line + "</p>");
        }
        Path template = projectRoot.resolve("src/main/resources/templates/comment.html");
        Files.createDirectories(template.getParent());
        Files.writeString(template, String.join("\n", lines));

        ReconSummary summary = new ReconService(mapper, embeddings).buildIndex(UUID.randomUUID(), projectRoot);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        List<CodeChunk> indexed = captor.getValue();
        assertThat(summary.sourceFileCount()).isEqualTo(1);
        assertThat(indexed).hasSizeGreaterThan(1);
        assertThat(indexed).allMatch(chunk -> chunk.getContent().length() <= 12_000);
        assertThat(indexed).anySatisfy(chunk -> {
            assertThat(chunk.getContent()).contains("v-html");
            assertThat(chunk.getStartLine()).isLessThanOrEqualTo(190);
            assertThat(chunk.getEndLine()).isGreaterThanOrEqualTo(190);
        });
    }

    @Test
    void detectsSecurityFrameworksAndAnnotationsAsReconFacts() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        EmbeddingService embeddings = mock(EmbeddingService.class);
        when(embeddings.embedAll(anyList())).thenAnswer(invocation -> {
            List<String> inputs = invocation.getArgument(0);
            List<double[]> vectors = new ArrayList<>();
            inputs.forEach(ignored -> vectors.add(new double[]{1, 0}));
            return vectors;
        });
        when(embeddings.serialize(org.mockito.ArgumentMatchers.any(double[].class))).thenReturn("1,0");

        Files.writeString(projectRoot.resolve("pom.xml"), """
                <project><dependencies><dependency>
                  <artifactId>spring-boot-starter-security</artifactId>
                </dependency></dependencies></project>
                """);
        Path controller = projectRoot.resolve("src/main/java/demo/AdminController.java");
        Files.createDirectories(controller.getParent());
        Files.writeString(controller, """
                package demo;
                import org.springframework.security.access.prepost.PreAuthorize;
                import org.springframework.web.bind.annotation.RestController;
                @RestController class AdminController {
                    @PreAuthorize("hasRole('ADMIN')") void deleteUser() {}
                }
                """);

        ReconSummary summary = new ReconService(mapper, embeddings).buildIndex(UUID.randomUUID(), projectRoot);

        assertThat(summary.technologyProfile().buildTools()).contains("Maven");
        assertThat(summary.technologyProfile().frameworks()).contains("Spring MVC");
        assertThat(summary.technologyProfile().securityFrameworks()).contains("Spring Security");
        assertThat(summary.technologyProfile().securityAnnotations()).contains("@PreAuthorize");
        assertThat(summary.technologyProfile().evidence()).anyMatch(item -> item.contains("pom.xml"));
    }
}
