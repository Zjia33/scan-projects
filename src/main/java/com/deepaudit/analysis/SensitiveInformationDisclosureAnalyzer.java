package com.deepaudit.analysis;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.GitFileChangeMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 为新增或修改的真实代码行生成敏感信息泄露调查线索。规则只负责定位候选，最终结论仍由专业 Agent 和 Critic 给出。
 */
@Order(40)
@Component
@RequiredArgsConstructor
public class SensitiveInformationDisclosureAnalyzer implements VulnerabilityAnalyzer {
    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)[\\\"']?([a-z0-9_.-]*(?:password|passwd|pwd|secret|api[-_.]?key|access[-_.]?key|"
                    + "secret[-_.]?key|private[-_.]?key|client[-_.]?secret|access[-_.]?token|"
                    + "refresh[-_.]?token|auth[-_.]?token|credential)[a-z0-9_.-]*)[\\\"']?\\s*[:=]\\s*(.+)$");
    private static final Pattern XML_VALUE = Pattern.compile(
            "(?i)<(password|passwd|pwd|secret|apiKey|accessKey|secretKey|privateKey|clientSecret|token|credential)>"
                    + "\\s*([^<]+)\\s*</\\1>");
    private static final Pattern CREDENTIAL_URI = Pattern.compile(
            "(?i)(?:jdbc:[a-z0-9]+:|https?|redis|mongodb(?:\\+srv)?):/{1,2}[^\\s/:@]+:([^\\s@/]+)@");
    private static final Pattern KNOWN_TOKEN = Pattern.compile(
            "(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----");

    private final GitFileChangeMapper changeMapper;

    @Override
    public VulnerabilityType type() {
        return VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE;
    }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        Map<String, GitFileChange> changes = changesByTargetPath(changeMapper.findByTaskId(context.taskId()));
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED) responseDisclosure(chunk, results);
            if (chunk.getAnalysisScope() != AnalysisScope.CHANGED) continue;
            GitFileChange change = changes.get(normalizePath(chunk.getFilePath()));
            if (change == null) continue;
            String[] lines = safe(chunk.getContent()).split("\\R", -1);
            for (int index = 0; index < lines.length; index++) {
                int absoluteLine = chunk.getStartLine() + index;
                if (!isTargetChangedLine(change, absoluteLine)) continue;
                SecretCandidate candidate = candidate(chunk.getFilePath(), lines[index]);
                if (candidate == null) continue;
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "代码仓库中可能包含硬编码敏感凭据", chunk.getFilePath(), absoluteLine, absoluteLine,
                        chunk.getEndpoint(),
                        "本次 Target 变更写入了" + candidate.kind() + "的字面量，可能导致凭据随源码传播或泄露。",
                        "规则提示（敏感值已隐藏，仅作为 Agent 调查起点）：\n"
                                + absoluteLine + " | " + candidate.redactedLine(),
                        "使用运行环境的 Secret 管理能力注入凭据，删除仓库中的真实值并按需轮换已暴露凭据。"));
            }
        }
        return List.copyOf(results);
    }

    private void responseDisclosure(CodeChunk chunk, List<FindingDraft> results) {
        if (chunk.getEndpoint() == null) return;
        boolean publicAccess = AnalyzerSupport.containsAny(chunk.getContent(),
                "permitall", "@anonymous", "@permitall")
                || AnalyzerSupport.containsAny(chunk.getEndpoint(), "/public/", "/open/", "/anonymous/");
        boolean sensitive = AnalyzerSupport.containsAny(chunk.getContent(),
                "password", "secret", "apikey", "privatekey", "idcard", "bankcard", "balance", "token", "salary");
        if (!publicAccess || !sensitive) return;
        int line = AnalyzerSupport.matchingLine(chunk,
                "password|secret|apiKey|privateKey|idCard|bankCard|balance|token|salary");
        results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                "公开接口可能暴露敏感信息", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                "无需授权访问的接口附近出现密码、令牌、身份或银行卡等敏感字段。",
                AnalyzerSupport.evidence(chunk, line),
                "要求登录和数据权限校验；使用专用响应 DTO，并通过字段白名单控制返回数据。"));
    }

    private Map<String, GitFileChange> changesByTargetPath(List<GitFileChange> changes) {
        Map<String, GitFileChange> result = new LinkedHashMap<>();
        if (changes == null) return result;
        for (GitFileChange change : changes) {
            if (change.getNewPath() != null) result.put(normalizePath(change.getNewPath()), change);
        }
        return result;
    }

    private boolean isTargetChangedLine(GitFileChange change, int line) {
        String ranges = change.getNewRanges();
        if ((ranges == null || ranges.isBlank()) && "ADD".equals(change.getChangeType())) return true;
        if (ranges == null || ranges.isBlank()) return false;
        for (String range : ranges.split(",")) {
            String[] bounds = range.split(":", 2);
            if (bounds.length != 2) continue;
            try {
                if (line >= Integer.parseInt(bounds[0]) && line <= Integer.parseInt(bounds[1])) return true;
            } catch (NumberFormatException ignored) {
                // 无效的差异范围不应扩大 Secret 扫描范围。
            }
        }
        return false;
    }

    private SecretCandidate candidate(String path, String sourceLine) {
        String line = safe(sourceLine).strip();
        if (line.isBlank() || line.startsWith("#") || line.startsWith("//")) return null;
        if (PRIVATE_KEY.matcher(line).find()) return redacted("私钥", line);
        if (CREDENTIAL_URI.matcher(line).find()) return redacted("连接凭据", line);
        if (KNOWN_TOKEN.matcher(line).find() && !placeholder(line)) return redacted("访问令牌", line);

        Matcher xml = XML_VALUE.matcher(line);
        if (xml.find() && hardcoded(xml.group(2), true)) return redacted(kind(xml.group(1)), line);

        Matcher assignment = KEY_VALUE.matcher(line);
        if (!assignment.find()) return null;
        String value = cleanValue(assignment.group(2));
        boolean configuration = isConfiguration(path);
        if (!hardcoded(value, configuration)) return null;
        return redacted(kind(assignment.group(1)), line);
    }

    private boolean hardcoded(String value, boolean configuration) {
        String normalized = cleanValue(value);
        if (normalized.isBlank() || placeholder(normalized)) return false;
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.equals("null") || lower.equals("none") || lower.equals("true") || lower.equals("false")
                || lower.startsWith("enc(") || lower.startsWith("{cipher}") || lower.startsWith("classpath:")
                || lower.contains("system.getenv") || lower.contains("system.getproperty")) return false;
        if (!configuration && !(normalized.startsWith("\"") || normalized.startsWith("'")
                || KNOWN_TOKEN.matcher(normalized).find())) return false;
        String unquoted = normalized.replaceAll("^[\\\"']|[\\\"']$", "").strip();
        return !unquoted.isBlank() && !placeholder(unquoted);
    }

    private boolean placeholder(String value) {
        String normalized = cleanValue(value).toLowerCase(Locale.ROOT);
        if (normalized.matches("\\$\\{[^}:]+(?::)?}")) return true;
        if (normalized.startsWith("#{") || normalized.matches("<[^>]+>")) return true;
        return normalized.contains("placeholder") || normalized.contains("example-value")
                || normalized.contains("dummy-value") || normalized.contains("your-" )
                || normalized.equals("test") || normalized.equals("sample");
    }

    private String cleanValue(String value) {
        String result = safe(value).strip();
        int comment = result.indexOf(" #");
        if (comment >= 0) result = result.substring(0, comment).strip();
        if (result.endsWith(",")) result = result.substring(0, result.length() - 1).strip();
        return result;
    }

    private boolean isConfiguration(String path) {
        String normalized = normalizePath(path).toLowerCase(Locale.ROOT);
        return normalized.endsWith(".yml") || normalized.endsWith(".yaml")
                || normalized.endsWith(".properties") || normalized.endsWith(".xml")
                || normalized.endsWith(".json") || normalized.endsWith(".conf")
                || normalized.endsWith(".ini") || normalized.endsWith(".env");
    }

    private SecretCandidate redacted(String kind, String line) {
        String prefix = line.strip().replaceAll("[:=].*$", ": <REDACTED_LITERAL>");
        if (prefix.equals(line.strip())) prefix = "<REDACTED_" + kind + ">";
        return new SecretCandidate(kind, prefix);
    }

    private String kind(String key) {
        String normalized = safe(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("private") && normalized.contains("key")) return "私钥";
        if (normalized.contains("token")) return "访问令牌";
        if (normalized.contains("api") && normalized.contains("key")) return "API Key";
        if (normalized.contains("access") && normalized.contains("key")) return "Access Key";
        if (normalized.contains("password") || normalized.contains("passwd") || normalized.endsWith("pwd")) {
            return "密码";
        }
        return "密钥或凭据";
    }

    private String normalizePath(String value) {
        return safe(value).replace('\\', '/');
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private record SecretCandidate(String kind, String redactedLine) {
    }
}
