package com.deepaudit.git;

import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class GitSnapshotServiceTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void materializesOnlyAuditableProductionSources() throws Exception {
        Path repositoryPath = temporaryDirectory.resolve("repository");
        write(repositoryPath, "src/main/java/demo/App.java", "class App {}");
        write(repositoryPath, "src/test/java/demo/AppTest.java", "class AppTest {}");
        write(repositoryPath, "target/generated-sources/demo/Generated.java", "class Generated {}");
        write(repositoryPath, "pom.xml", "<project/>");

        try (Git git = Git.init().setDirectory(repositoryPath.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String commit = git.commit().setMessage("source filter")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid")
                    .call().getId().name();

            Path snapshot = temporaryDirectory.resolve("snapshot");
            GitSnapshotService.SnapshotResult result = new GitSnapshotService(new GitProperties())
                    .materialize(git.getRepository(), commit, snapshot);

            assertThat(result.fileCount()).isEqualTo(2);
            assertThat(result.skippedFileCount()).isEqualTo(2);
            assertThat(snapshot.resolve("src/main/java/demo/App.java")).isRegularFile();
            assertThat(snapshot.resolve("pom.xml")).isRegularFile();
            assertThat(snapshot.resolve("src/test/java/demo/AppTest.java")).doesNotExist();
            assertThat(snapshot.resolve("target/generated-sources/demo/Generated.java")).doesNotExist();
        }
    }

    @Test
    void reusesCommitSnapshotCacheAcrossAudits() throws Exception {
        Path repositoryPath = temporaryDirectory.resolve("cached-repository");
        write(repositoryPath, "src/main/java/demo/App.java", "class App {}");
        try (Git git = Git.init().setDirectory(repositoryPath.toFile()).call()) {
            git.add().addFilepattern(".").call();
            String commit = git.commit().setMessage("cached snapshot")
                    .setAuthor("DeepAudit Test", "test@example.invalid")
                    .setCommitter("DeepAudit Test", "test@example.invalid")
                    .call().getId().name();
            GitSnapshotService service = new GitSnapshotService(new GitProperties());
            Path cache = temporaryDirectory.resolve("commit-cache");

            GitSnapshotService.SnapshotResult first = service.materializeCached(
                    git.getRepository(), commit, cache);
            GitSnapshotService.SnapshotResult second = service.materializeCached(
                    git.getRepository(), commit, cache);

            assertThat(second).isEqualTo(first);
            assertThat(cache.resolve(commit).resolve("src/main/java/demo/App.java")).isRegularFile();
            assertThat(cache.resolve(commit + ".snapshot")).isRegularFile();
        }
    }

    private void write(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
