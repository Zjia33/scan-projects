package com.deepaudit.recon;

import com.deepaudit.source.AuditSourceFilter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

@Slf4j
final class ProjectTechnologyDetector {
    private static final long MAX_FILE_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_EVIDENCE = 80;
    private static final Set<String> INSPECTED_EXTENSIONS = Set.of(
            "java", "xml", "yml", "yaml", "properties", "gradle", "kts", "json",
            "html", "jsp", "ftl", "vue", "jsx", "tsx", "js", "ts"
    );

    // 从构建文件和源码标记中确定性识别框架、安全组件与持久化技术。
    TechnologyProfile detect(Path root) {
        Detection detection = new Detection(root);
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.shouldAnalyze(root, path))
                    .filter(this::isInspectable)
                    .forEach(detection::inspect);
        } catch (IOException exception) {
            log.warn("项目技术栈探测未完整执行: {}", root, exception);
        }
        return detection.profile();
    }

    // 仅检查有限大小的构建配置和受支持文本源码。
    private boolean isInspectable(Path file) {
        try {
            if (Files.size(file) > MAX_FILE_BYTES) return false;
        } catch (IOException exception) {
            return false;
        }
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.equals("pom.xml") || name.equals("package.json") || name.startsWith("build.gradle")
                || name.startsWith("settings.gradle")) return true;
        int dot = name.lastIndexOf('.');
        return dot > 0 && INSPECTED_EXTENSIONS.contains(name.substring(dot + 1));
    }

    private static final class Detection {
        private final Path root;
        private final Set<String> frameworks = new LinkedHashSet<>();
        private final Set<String> securityFrameworks = new LinkedHashSet<>();
        private final Set<String> persistenceFrameworks = new LinkedHashSet<>();
        private final Set<String> buildTools = new LinkedHashSet<>();
        private final Set<String> securityAnnotations = new LinkedHashSet<>();
        private final Set<String> evidence = new LinkedHashSet<>();

        private Detection(Path root) {
            this.root = root;
        }

        // 扫描单个文件的技术标记并保留有限条来源证据。
        private void inspect(Path file) {
            try {
                String relative = root.relativize(file).toString().replace('\\', '/');
                String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
                String content = Files.readString(file, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                if (name.equals("pom.xml")) add(buildTools, "Maven", relative, "pom.xml");
                if (name.startsWith("build.gradle") || name.startsWith("settings.gradle")) {
                    add(buildTools, "Gradle", relative, name);
                }

                detect(content, relative, frameworks, "Spring Boot", "spring-boot", "@springbootapplication");
                detect(content, relative, frameworks, "Spring MVC", "spring-boot-starter-web",
                        "spring-webmvc", "@restcontroller", "@requestmapping");
                detect(content, relative, frameworks, "Spring WebFlux", "spring-boot-starter-webflux",
                        "webfluxconfigurer", "routerfunction<");
                detect(content, relative, frameworks, "Jakarta Servlet", "jakarta.servlet", "javax.servlet");
                detect(content, relative, frameworks, "Apache Struts", "struts2-core", "org.apache.struts");
                detect(content, relative, frameworks, "Vue", "\"vue\"", ".vue");
                detect(content, relative, frameworks, "React", "\"react\"", "react-dom");
                detect(content, relative, frameworks, "Thymeleaf", "thymeleaf", "th:");
                detect(content, relative, frameworks, "FreeMarker", "freemarker", ".ftl");

                detect(content, relative, securityFrameworks, "Spring Security", "spring-security",
                        "spring-boot-starter-security", "securityfilterchain", "@enablewebsecurity");
                detect(content, relative, securityFrameworks, "Apache Shiro", "org.apache.shiro",
                        "shiro-spring", "@requirespermissions", "@requiresroles");
                detect(content, relative, securityFrameworks, "Sa-Token", "sa-token", "cn.dev33.satoken",
                        "@sacheckpermission", "@sacheckrole", "stputil");
                detect(content, relative, securityFrameworks, "Keycloak", "keycloak-spring", "keycloak-admin-client");
                detect(content, relative, securityFrameworks, "Jakarta Security", "jakarta.annotation.security",
                        "javax.annotation.security");

                detect(content, relative, persistenceFrameworks, "MyBatis", "mybatis", "@mapper",
                        "sqlsession", "<mapper");
                detect(content, relative, persistenceFrameworks, "JPA / Hibernate", "spring-boot-starter-data-jpa",
                        "org.hibernate", "jakarta.persistence", "javax.persistence", "@entity");
                detect(content, relative, persistenceFrameworks, "Spring JDBC", "jdbctemplate", "namedparameterjdbctemplate");
                detect(content, relative, persistenceFrameworks, "jOOQ", "org.jooq", "dslcontext");

                annotation(content, relative, "@PreAuthorize", "@preauthorize");
                annotation(content, relative, "@PostAuthorize", "@postauthorize");
                annotation(content, relative, "@Secured", "@secured");
                annotation(content, relative, "@RolesAllowed", "@rolesallowed");
                annotation(content, relative, "@PermitAll", "@permitall");
                annotation(content, relative, "@DenyAll", "@denyall");
                annotation(content, relative, "@RequiresPermissions", "@requirespermissions");
                annotation(content, relative, "@RequiresRoles", "@requiresroles");
                annotation(content, relative, "@SaCheckPermission", "@sacheckpermission");
                annotation(content, relative, "@SaCheckRole", "@sacheckrole");
            } catch (Exception exception) {
                log.debug("跳过无法探测技术栈的文件: {}", file, exception);
            }
        }

        private void annotation(String content, String relative, String annotation, String marker) {
            if (content.contains(marker)) add(securityAnnotations, annotation, relative, marker);
        }

        private void detect(String content, String relative, Set<String> target, String technology,
                            String... markers) {
            for (String marker : markers) {
                if ((marker.startsWith(".") && relative.toLowerCase(Locale.ROOT).endsWith(marker))
                        || content.contains(marker)) {
                    add(target, technology, relative, marker);
                    return;
                }
            }
        }

        private void add(Set<String> target, String value, String relative, String marker) {
            target.add(value);
            if (evidence.size() < MAX_EVIDENCE) evidence.add(value + " <- " + relative + " [" + marker + "]");
        }

        // 将去重后的探测集合冻结为 Recon 可消费的技术栈事实。
        private TechnologyProfile profile() {
            return new TechnologyProfile(frameworks.stream().toList(), securityFrameworks.stream().toList(),
                    persistenceFrameworks.stream().toList(), buildTools.stream().toList(),
                    securityAnnotations.stream().toList(), evidence.stream().toList());
        }
    }
}
