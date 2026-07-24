package com.deepaudit.git;

import com.deepaudit.domain.Project;
import com.deepaudit.domain.ProjectSourceType;
import com.deepaudit.mapper.ProjectMapper;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.revwalk.filter.RevFilter;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class GitRepositoryService {
    private final ProjectMapper projectMapper;
    private final GitProperties properties;
    private final Path storageRoot;

    public GitRepositoryService(ProjectMapper projectMapper, GitProperties properties,
                                @Value("${deepaudit.storage-root:./data}") String storageRoot) {
        this.projectMapper = projectMapper;
        this.properties = properties;
        this.storageRoot = Path.of(storageRoot).toAbsolutePath().normalize();
    }

    // 克隆只读裸仓库；凭据只在当前请求内使用，不写入项目记录或日志。
    public ImportedRepository importRepository(String requestedName, String repositoryUrl,
                                               String username, String accessToken) throws IOException {
        long startedAt = System.nanoTime();
        String normalizedUrl = validateRepositoryUrl(repositoryUrl);
        CredentialsProvider credentialProvider = credentials(normalizedUrl, username, accessToken);
        UUID projectId = UUID.randomUUID();
        Path projectDirectory = storageRoot.resolve("repositories").resolve(projectId.toString()).normalize();
        requireWithinStorage(projectDirectory);
        Path bareRepository = projectDirectory.resolve("source.git").normalize();
        log.info("开始读取并导入 Git 仓库：projectId={}，source={}，bare=true，authentication={}",
                projectId, repositoryLabel(normalizedUrl),
                credentialProvider == null ? "ANONYMOUS" : "TOKEN");
        Files.createDirectories(projectDirectory);
        try {
            var command = Git.cloneRepository()
                    .setURI(normalizedUrl)
                    .setDirectory(bareRepository.toFile())
                    .setBare(true)
                    .setCloneAllBranches(true)
                    .setNoCheckout(true)
                    .setTimeout(clampedTimeout());
            if (credentialProvider != null) command.setCredentialsProvider(credentialProvider);
            try (Git git = command.call()) {
                Repository repository = git.getRepository();
                String defaultBranch = defaultBranch(repository);
                String name = sanitizeName(requestedName, normalizedUrl);
                List<CommitInfo> commitInfos = commits(repository, properties.getMaxCommits());
                Project project = new Project(projectId, name, normalizedUrl, bareRepository.toString(),
                        ProjectSourceType.GIT, normalizedUrl, defaultBranch);
                projectMapper.insert(project);
                log.info("Git 仓库导入完成：projectId={}，defaultBranch={}，commitCount={}，elapsedMs={}",
                        projectId, defaultBranch, commitInfos.size(), elapsedMillis(startedAt));
                return new ImportedRepository(project, commitInfos);
            }
        } catch (Exception exception) {
            log.warn("Git 仓库导入失败：projectId={}，source={}，errorType={}，message={}",
                    projectId, repositoryLabel(normalizedUrl), exception.getClass().getSimpleName(),
                    safeMessage(exception));
            deleteTree(projectDirectory);
            throw new IllegalArgumentException(repositoryReadFailure(
                    normalizedUrl, exception, credentialProvider != null), exception);
        }
    }

    public List<Project> projects() {
        return projectMapper.findAllOrderByCreatedAtDesc().stream()
                .filter(project -> project.getSourceType() == ProjectSourceType.GIT)
                .toList();
    }

    public List<CommitInfo> commits(UUID projectId, int requestedLimit) throws IOException {
        long startedAt = System.nanoTime();
        Project project = requireGitProject(projectId);
        int limit = Math.min(Math.max(requestedLimit, 1), properties.getMaxCommits());
        log.info("开始读取 Git 提交记录：projectId={}，limit={}", projectId, limit);
        try (Repository repository = open(project)) {
            List<CommitInfo> result = commits(repository, limit);
            log.info("Git 提交记录读取完成：projectId={}，commitCount={}，elapsedMs={}",
                    projectId, result.size(), elapsedMillis(startedAt));
            return result;
        } catch (IOException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IOException("读取 Git 提交记录失败", exception);
        }
    }

    public List<CommitInfo> refresh(UUID projectId, String username, String accessToken) throws IOException {
        long startedAt = System.nanoTime();
        Project project = requireGitProject(projectId);
        CredentialsProvider credentialProvider = credentials(project.getRepositoryUrl(), username, accessToken);
        log.info("开始刷新 Git 远端引用：projectId={}，source={}",
                projectId, repositoryLabel(project.getRepositoryUrl()));
        try (Repository repository = open(project); Git git = new Git(repository)) {
            var fetch = git.fetch().setRemote("origin").setRemoveDeletedRefs(true).setTimeout(clampedTimeout());
            if (credentialProvider != null) fetch.setCredentialsProvider(credentialProvider);
            fetch.call();
            List<CommitInfo> result = commits(repository, properties.getMaxCommits());
            log.info("Git 远端引用刷新完成：projectId={}，commitCount={}，elapsedMs={}",
                    projectId, result.size(), elapsedMillis(startedAt));
            return result;
        } catch (Exception exception) {
            log.warn("Git 远端引用刷新失败：projectId={}，errorType={}，message={}",
                    projectId, exception.getClass().getSimpleName(), safeMessage(exception));
            throw new IllegalArgumentException(repositoryReadFailure(
                    project.getRepositoryUrl(), exception, credentialProvider != null), exception);
        }
    }

    public ResolvedComparison resolveComparison(Project project, String baseRevision,
                                                String targetRevision, boolean incremental) throws IOException {
        log.info("开始解析审计提交：projectId={}，mode={}，base={}，target={}",
                project.getId(), incremental ? "INCREMENTAL" : "FULL",
                incremental ? shortSha(baseRevision) : "-", shortSha(targetRevision));
        try (Repository repository = open(project); RevWalk walk = new RevWalk(repository)) {
            RevCommit target = resolveCommit(repository, walk, targetRevision);
            if (!incremental) {
                log.info("全量审计提交解析完成：projectId={}，target={}",
                        project.getId(), shortSha(target.getId().name()));
                return new ResolvedComparison(null, target.getId().name(), null);
            }
            RevCommit base = resolveCommit(repository, walk, baseRevision);
            if (base.equals(target)) throw new IllegalArgumentException("Base 和 Target 不能是同一个提交");
            boolean ancestor = walk.isMergedInto(base, target);
            String mergeBase = ancestor ? base.getId().name() : mergeBase(repository, base, target);
            if (!ancestor) {
                throw new IllegalArgumentException("Base 必须是 Target 的祖先提交；共同祖先为 " + shortSha(mergeBase));
            }
            log.info("增量审计提交解析完成：projectId={}，base={}，target={}，mergeBase={}",
                    project.getId(), shortSha(base.getId().name()), shortSha(target.getId().name()),
                    shortSha(mergeBase));
            return new ResolvedComparison(base.getId().name(), target.getId().name(), mergeBase);
        }
    }

    public Project requireGitProject(UUID projectId) {
        Project project = projectMapper.findById(projectId);
        if (project == null || project.getSourceType() != ProjectSourceType.GIT) {
            throw new java.util.NoSuchElementException("Git 项目不存在: " + projectId);
        }
        return project;
    }

    public Repository open(Project project) throws IOException {
        Path gitDirectory = Path.of(project.getStoragePath()).toAbsolutePath().normalize();
        requireWithinStorage(gitDirectory);
        return new FileRepositoryBuilder().setGitDir(gitDirectory.toFile()).setBare().build();
    }

    private List<CommitInfo> commits(Repository repository, int limit) throws Exception {
        List<CommitInfo> result = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        try (Git git = new Git(repository)) {
            for (RevCommit commit : git.log().all().setMaxCount(limit * 3).call()) {
                if (!seen.add(commit.getId().name())) continue;
                result.add(new CommitInfo(commit.getId().name(), shortSha(commit.getId().name()),
                        commit.getShortMessage(), commit.getAuthorIdent().getName(),
                        commit.getAuthorIdent().getWhenAsInstant()));
                if (result.size() >= limit) break;
            }
        }
        result.sort(Comparator.comparing(CommitInfo::committedAt).reversed());
        return List.copyOf(result);
    }

    private RevCommit resolveCommit(Repository repository, RevWalk walk, String revision) throws IOException {
        if (revision == null || revision.isBlank()) throw new IllegalArgumentException("必须选择提交");
        ObjectId objectId = repository.resolve(revision.strip());
        if (objectId == null) throw new IllegalArgumentException("仓库中不存在提交: " + revision);
        return walk.parseCommit(objectId);
    }

    private String mergeBase(Repository repository, RevCommit left, RevCommit right) throws IOException {
        try (RevWalk mergeWalk = new RevWalk(repository)) {
            mergeWalk.setRevFilter(RevFilter.MERGE_BASE);
            mergeWalk.markStart(mergeWalk.parseCommit(left));
            mergeWalk.markStart(mergeWalk.parseCommit(right));
            RevCommit common = mergeWalk.next();
            if (common == null) throw new IllegalArgumentException("两个提交不存在共同祖先");
            return common.getId().name();
        }
    }

    private String defaultBranch(Repository repository) throws IOException {
        Ref head = repository.exactRef(Constants.HEAD);
        if (head != null && head.isSymbolic() && head.getTarget() != null) {
            return Repository.shortenRefName(head.getTarget().getName());
        }
        return "main";
    }

    private String validateRepositoryUrl(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Git 仓库地址不能为空");
        URI uri;
        try {
            uri = URI.create(value.strip());
        } catch (Exception exception) {
            throw new IllegalArgumentException("Git 仓库地址格式不正确");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if ("file".equals(scheme)) {
            if (!properties.isAllowLocalRepositories()) {
                throw new IllegalArgumentException("当前环境不允许导入本地 Git 仓库");
            }
            return uri.toString();
        }
        if (!"https".equals(scheme) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("只允许不含内嵌凭据的 HTTPS Git 仓库地址");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        boolean allowed = properties.getAllowedHosts().stream()
                .map(item -> item.toLowerCase(Locale.ROOT).strip())
                .anyMatch(item -> host.equals(item));
        if (!allowed) throw new IllegalArgumentException("Git 主机不在允许列表中: " + host);
        return uri.toString();
    }

    private CredentialsProvider credentials(String repositoryUrl, String username, String accessToken) {
        NormalizedCredentials normalized = normalizeCredentials(repositoryUrl, username, accessToken);
        if (normalized == null) return null;
        return new UsernamePasswordCredentialsProvider(normalized.username(), normalized.accessToken());
    }

    // 清除复制令牌时可能带入的空白；GitHub 用户名缺省时使用仓库所有者作为非空用户名。
    static NormalizedCredentials normalizeCredentials(String repositoryUrl, String username, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) return null;
        String effectiveUsername = username == null || username.isBlank()
                ? defaultCredentialUsername(repositoryUrl)
                : username.strip();
        return new NormalizedCredentials(effectiveUsername, accessToken.strip());
    }

    private static String defaultCredentialUsername(String repositoryUrl) {
        try {
            URI uri = URI.create(repositoryUrl);
            if ("github.com".equalsIgnoreCase(uri.getHost())) {
                String path = uri.getPath();
                if (path != null) {
                    for (String segment : path.split("/")) {
                        if (!segment.isBlank()) return segment;
                    }
                }
            }
        } catch (Exception ignored) {
            // 地址已在调用凭据处理前校验；这里只保留安全的非空兜底用户名。
        }
        return "oauth2";
    }

    // 将 JGit 的底层认证/网络消息转换成可操作且不泄露令牌的接口提示。
    static String repositoryReadFailure(String repositoryUrl, Exception exception, boolean credentialsProvided) {
        String details = exceptionDetails(exception).toLowerCase(Locale.ROOT);
        boolean authenticationFailure = details.contains("authentication is required")
                || details.contains("not authorized")
                || details.contains("unauthorized")
                || details.contains("forbidden")
                || details.contains("not permitted");
        if (authenticationFailure) {
            if (!credentialsProvided) {
                return "该 Git 仓库需要认证，请填写 Git 用户名和访问令牌";
            }
            if (isGitHub(repositoryUrl)) {
                return "GitHub 已拒绝读取该仓库：请确认令牌仍有效、已授权目标仓库，并具有 Contents: Read 权限";
            }
            return "Git 主机已拒绝读取该仓库，请确认令牌有效且具有仓库读取权限";
        }
        boolean connectionFailure = details.contains("connection failed")
                || details.contains("connection refused")
                || details.contains("connect timed out")
                || details.contains("read timed out")
                || details.contains("unknown host")
                || details.contains("unable to resolve host");
        if (connectionFailure) {
            return "无法连接 Git 主机，请检查 JVM 代理、DNS 和防火墙配置";
        }
        return "无法读取 Git 仓库，请检查地址、访问权限和网络连接";
    }

    private static boolean isGitHub(String repositoryUrl) {
        try {
            return "github.com".equalsIgnoreCase(URI.create(repositoryUrl).getHost());
        } catch (Exception ignored) {
            return false;
        }
    }

    private static String exceptionDetails(Exception exception) {
        StringBuilder details = new StringBuilder();
        Throwable current = exception;
        int depth = 0;
        while (current != null && depth++ < 8) {
            if (current.getMessage() != null) details.append(' ').append(current.getMessage());
            current = current.getCause();
        }
        return details.toString();
    }

    private String sanitizeName(String requestedName, String repositoryUrl) {
        String value = requestedName == null || requestedName.isBlank()
                ? repositoryUrl.substring(repositoryUrl.lastIndexOf('/') + 1).replaceFirst("\\.git$", "")
                : requestedName;
        String sanitized = value.replaceAll("[\\r\\n\\t<>]", " ").strip();
        return sanitized.isBlank() ? "未命名 Git 项目" : sanitized.substring(0, Math.min(200, sanitized.length()));
    }

    private int clampedTimeout() {
        return Math.max(10, Math.min(properties.getTransportTimeoutSeconds(), 300));
    }

    private void requireWithinStorage(Path path) {
        if (!path.startsWith(storageRoot)) throw new IllegalArgumentException("Git 存储路径非法");
    }

    private void deleteTree(Path root) {
        if (root == null || !root.startsWith(storageRoot) || !Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (IOException ignored) { }
            });
        } catch (IOException ignored) {
        }
    }

    private String shortSha(String sha) {
        return sha == null ? "" : sha.substring(0, Math.min(8, sha.length()));
    }

    private String repositoryLabel(String repositoryUrl) {
        if (repositoryUrl == null || repositoryUrl.isBlank()) return "unknown";
        try {
            URI uri = URI.create(repositoryUrl);
            if ("file".equalsIgnoreCase(uri.getScheme())) return "local-file-repository";
            String path = uri.getPath() == null ? "" : uri.getPath();
            return uri.getHost() + path;
        } catch (Exception ignored) {
            return "invalid-repository-url";
        }
    }

    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000;
    }

    private String safeMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) return "无详细信息";
        String normalized = message.replaceAll("[\\r\\n\\t]+", " ");
        return normalized.substring(0, Math.min(normalized.length(), 300));
    }

    public record CommitInfo(String sha, String shortSha, String message, String author, Instant committedAt) {
    }

    public record ImportedRepository(Project project, List<CommitInfo> commits) {
    }

    public record ResolvedComparison(String baseCommitSha, String targetCommitSha, String mergeBaseSha) {
    }

    record NormalizedCredentials(String username, String accessToken) {
    }
}
