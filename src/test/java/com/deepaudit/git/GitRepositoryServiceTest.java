package com.deepaudit.git;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitRepositoryServiceTest {

    @Test
    void allowsHttpForHostPresentInBothHostAllowLists() {
        GitRepositoryService service = repositoryService(
                List.of("github.com", "dev.nbcb.com"), List.of("dev.nbcb.com"));

        assertThat(service.validateRepositoryUrl(
                "http://dev.nbcb.com:30005/enterprise/enterprise__EA/xfb-irenshi-staff.git"))
                .isEqualTo("http://dev.nbcb.com:30005/enterprise/enterprise__EA/xfb-irenshi-staff.git");
    }

    @Test
    void rejectsHttpWhenHostIsMissingFromDedicatedHttpAllowList() {
        GitRepositoryService service = repositoryService(List.of("dev.nbcb.com"), List.of());

        assertThatThrownBy(() -> service.validateRepositoryUrl(
                "http://dev.nbcb.com:30005/enterprise/repository.git"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Git 主机未获准使用 HTTP: dev.nbcb.com");
    }

    @Test
    void keepsHttpsAvailableWithoutDedicatedHttpPermission() {
        GitRepositoryService service = repositoryService(List.of("dev.nbcb.com"), List.of());

        assertThat(service.validateRepositoryUrl("https://dev.nbcb.com:30005/enterprise/repository.git"))
                .isEqualTo("https://dev.nbcb.com:30005/enterprise/repository.git");
    }

    @Test
    void doesNotTreatSubdomainsAsAnImplicitHttpAllowListMatch() {
        GitRepositoryService service = repositoryService(
                List.of("dev.nbcb.com", "child.dev.nbcb.com"), List.of("dev.nbcb.com"));

        assertThatThrownBy(() -> service.validateRepositoryUrl(
                "http://child.dev.nbcb.com:30005/enterprise/repository.git"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Git 主机未获准使用 HTTP: child.dev.nbcb.com");
    }

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

    private GitRepositoryService repositoryService(List<String> allowedHosts,
                                                   List<String> allowedHttpHosts) {
        GitProperties properties = new GitProperties();
        properties.setAllowedHosts(allowedHosts);
        properties.setAllowedHttpHosts(allowedHttpHosts);
        return new GitRepositoryService(null, properties, ".");
    }
}
