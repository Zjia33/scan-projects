package com.deepaudit.git;

import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class GitDiffServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void buildsStructuredRangesAndConfigurationFacts() throws Exception {
        Path repositoryPath = temporaryDirectory.resolve("repository");
        Path source = repositoryPath.resolve("src/main/java/demo/App.java");
        Path config = repositoryPath.resolve("pom.xml");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "class App {\n  void safe() {}\n}\n", StandardCharsets.UTF_8);
        Files.writeString(config, "<project><version>1</version></project>", StandardCharsets.UTF_8);
        try (Git git = Git.init().setDirectory(repositoryPath.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String base = commit(git, "base");
            Files.writeString(source, "class App {\n  void unsafe(String input) { execute(input); }\n}\n",
                    StandardCharsets.UTF_8);
            Files.writeString(config, "<project><version>2</version></project>", StandardCharsets.UTF_8);
            git.add().addFilepattern(".").call();
            String target = commit(git, "target");

            GitDiffService.ChangeSet result = new GitDiffService().compare(
                    git.getRepository(), UUID.randomUUID(), base, target);

            assertThat(result.changes()).hasSize(2);
            assertThat(result.summary()).contains("2 个文件发生变化");
            assertThat(result.changes()).anySatisfy(change -> {
                if ("src/main/java/demo/App.java".equals(change.getNewPath())) {
                    assertThat(change.getChangeType()).isEqualTo("MODIFY");
                    assertThat(change.getNewRanges()).isNotBlank();
                    assertThat(change.getContextText()).contains("  class App {", "+   void unsafe", "  }");
                }
            });
            assertThat(result.changes()).filteredOn(change -> "pom.xml".equals(change.getNewPath()))
                    .allSatisfy(change -> assertThat(change.isConfigurationChange()).isTrue());
        }
    }

    @Test
    void excludesTestAndGeneratedFileChangesFromIncrementalScope() throws Exception {
        Path repositoryPath = temporaryDirectory.resolve("filtered-repository");
        Path source = repositoryPath.resolve("src/main/java/demo/App.java");
        Path test = repositoryPath.resolve("src/test/java/demo/AppTest.java");
        Path generated = repositoryPath.resolve("target/generated-sources/demo/Generated.java");
        Path documentation = repositoryPath.resolve("README.md");
        Path frontend = repositoryPath.resolve("frontend/src/App.ts");
        Files.createDirectories(source.getParent());
        Files.createDirectories(test.getParent());
        Files.createDirectories(generated.getParent());
        Files.createDirectories(frontend.getParent());
        Files.writeString(source, "class App { void run() {} }\n");
        Files.writeString(test, "class AppTest { void testRun() {} }\n");
        Files.writeString(generated, "class Generated { void call() {} }\n");
        Files.writeString(documentation, "# Base\n");
        Files.writeString(frontend, "export const safe = true;\n");

        try (Git git = Git.init().setDirectory(repositoryPath.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String base = commit(git, "base");
            Files.writeString(source, "class App { void run() { secure(); } }\n");
            Files.writeString(test, "class AppTest { void testRun() { execute(\"unsafe\"); } }\n");
            Files.writeString(generated, "class Generated { void call() { execute(\"unsafe\"); } }\n");
            Files.writeString(documentation, "# Target\n");
            Files.writeString(frontend, "export const safe = false;\n");
            git.add().addFilepattern(".").call();
            String target = commit(git, "target");

            GitDiffService.ChangeSet result = new GitDiffService().compare(
                    git.getRepository(), UUID.randomUUID(), base, target);

            assertThat(result.changes()).singleElement()
                    .satisfies(change -> assertThat(change.getNewPath())
                            .isEqualTo("src/main/java/demo/App.java"));
            assertThat(result.summary()).contains("1 个文件发生变化");
        }
    }

    @Test
    void preservesOldRangeWhenAHunkOnlyDeletesSecurityCode() throws Exception {
        Path repositoryPath = temporaryDirectory.resolve("deletion-repository");
        Path source = repositoryPath.resolve("src/main/java/demo/OrderService.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                class OrderService {
                  Object load(Long id) {
                    checkOwner(id);
                    return repository.findById(id);
                  }
                }
                """);
        try (Git git = Git.init().setDirectory(repositoryPath.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String base = commit(git, "base with guard");
            Files.writeString(source, """
                    class OrderService {
                      Object load(Long id) {
                        return repository.findById(id);
                      }
                    }
                    """);
            git.add().addFilepattern(".").call();
            String target = commit(git, "remove guard");

            GitDiffService.ChangeSet result = new GitDiffService().compare(
                    git.getRepository(), UUID.randomUUID(), base, target);

            assertThat(result.changes()).singleElement().satisfies(change -> {
                assertThat(change.getOldRanges()).isNotBlank();
                assertThat(change.getNewRanges()).isBlank();
                assertThat(change.getContextText()).contains("-     checkOwner(id);");
            });
        }
    }

    private String commit(Git git, String message) throws Exception {
        return git.commit().setMessage(message)
                .setAuthor("DeepAudit Test", "test@example.invalid")
                .setCommitter("DeepAudit Test", "test@example.invalid")
                .call().getId().name();
    }
}
