package com.deepaudit.git;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GitRepositoryServiceTest {

    @Test
    void normalizesCopiedCredentialsAndUsesGitHubOwnerAsDefaultUsername() {
        GitRepositoryService.NormalizedCredentials credentials = GitRepositoryService.normalizeCredentials(
                "https://github.com/Zjia33/Code-Security-Review.git", "  ", "  test-token\r\n");

        assertThat(credentials).isNotNull();
        assertThat(credentials.username()).isEqualTo("Zjia33");
        assertThat(credentials.accessToken()).isEqualTo("test-token");
    }

    @Test
    void omitsCredentialsWhenTokenIsBlank() {
        assertThat(GitRepositoryService.normalizeCredentials(
                "https://github.com/Zjia33/Code-Security-Review.git", "Zjia33", " \r\n"))
                .isNull();
    }

    @Test
    void explainsGitHubUploadPackRejectionAsAuthorizationFailure() {
        String message = GitRepositoryService.repositoryReadFailure(
                "https://github.com/Zjia33/Code-Security-Review.git",
                new IllegalStateException("git-upload-pack not permitted on repository"),
                true);

        assertThat(message)
                .contains("GitHub 已拒绝读取")
                .contains("Contents: Read")
                .doesNotContain("test-token");
    }

    @Test
    void distinguishesMissingCredentialsFromRejectedCredentials() {
        String message = GitRepositoryService.repositoryReadFailure(
                "https://github.com/Zjia33/Code-Security-Review.git",
                new IllegalStateException("Authentication is required but no CredentialsProvider has been registered"),
                false);

        assertThat(message).isEqualTo("该 Git 仓库需要认证，请填写 Git 用户名和访问令牌");
    }

    @Test
    void explainsConnectionFailureAsProxyOrNetworkProblem() {
        String message = GitRepositoryService.repositoryReadFailure(
                "https://github.com/Zjia33/Code-Security-Review.git",
                new IllegalStateException("connection failed"),
                true);

        assertThat(message).contains("JVM 代理");
    }
}
