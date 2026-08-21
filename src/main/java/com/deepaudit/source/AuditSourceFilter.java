package com.deepaudit.source;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

/** Classifies repository paths into the explicitly supported backend audit roles. */
public final class AuditSourceFilter {
    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of(
            ".git", ".github", ".idea", ".vscode", ".gradle", ".codegraph-deepaudit",
            "target", "build", "out", "dist", "coverage",
            "node_modules", "bower_components", "vendor", "third_party", "third-party",
            "generated", "generated-sources", "generated-test-sources",
            "test", "tests", "__tests__", "testfixtures", "test-fixtures",
            "testdata", "test-data", "__fixtures__", "androidtest",
            "integrationtest", "integration-test", "docs", "documentation",
            ".nyc_output", ".pytest_cache", "__pycache__"
    );
    private static final Set<String> TEST_METHOD_ANNOTATIONS = Set.of(
            "Test", "ParameterizedTest", "RepeatedTest", "TestFactory", "TestTemplate",
            "Before", "After", "BeforeClass", "AfterClass",
            "BeforeEach", "AfterEach", "BeforeAll", "AfterAll",
            "BeforeMethod", "AfterMethod", "BeforeSuite", "AfterSuite",
            "BeforeTest", "AfterTest", "BeforeGroups", "AfterGroups"
    );

    private AuditSourceFilter() {
    }

    public static AuditFileRole classify(Path root, Path candidate) {
        if (root == null || candidate == null) return AuditFileRole.IGNORE;
        try {
            return classify(root.toAbsolutePath().normalize()
                    .relativize(candidate.toAbsolutePath().normalize()).toString());
        } catch (IllegalArgumentException exception) {
            return AuditFileRole.IGNORE;
        }
    }

    public static AuditFileRole classify(String repositoryPath) {
        if (repositoryPath == null) return AuditFileRole.IGNORE;
        String normalized = repositoryPath.replace('\\', '/');
        while (normalized.startsWith("./")) normalized = normalized.substring(2);
        while (normalized.contains("//")) normalized = normalized.replace("//", "/");
        if (normalized.isBlank()) return AuditFileRole.IGNORE;

        String[] segments = normalized.split("/");
        for (String segment : segments) {
            if (EXCLUDED_DIRECTORIES.contains(segment.toLowerCase(Locale.ROOT))) {
                return AuditFileRole.IGNORE;
            }
        }
        String fileName = segments[segments.length - 1];
        if (isConventionalTestFile(fileName) || isGeneratedAsset(fileName)) return AuditFileRole.IGNORE;

        String lowerName = fileName.toLowerCase(Locale.ROOT);
        String lowerPath = normalized.toLowerCase(Locale.ROOT);
        if (isBuildDescriptor(lowerName)) return AuditFileRole.BUILD_METADATA;
        if (lowerName.endsWith(".java")) return AuditFileRole.JAVA_SOURCE;
        if (isEnvironmentFile(lowerName) || lowerName.endsWith(".properties")
                || lowerName.endsWith(".yml") || lowerName.endsWith(".yaml")) {
            return AuditFileRole.SECURITY_CONFIGURATION;
        }
        if (lowerName.endsWith(".sql")) return AuditFileRole.DATA_ACCESS;
        if (lowerName.endsWith(".xml") && isDataAccessXml(lowerPath, lowerName)) {
            return AuditFileRole.DATA_ACCESS;
        }
        if (isSecurityConfigurationXml(lowerPath, lowerName)) {
            return AuditFileRole.SECURITY_CONFIGURATION;
        }
        if (lowerName.endsWith(".jsp") || lowerName.endsWith(".ftl")
                || isServerHtmlTemplate(lowerPath, lowerName)) {
            return AuditFileRole.SERVER_TEMPLATE;
        }
        return AuditFileRole.IGNORE;
    }

    public static boolean isFrameworkContext(String repositoryPath) {
        AuditFileRole role = classify(repositoryPath);
        if (role == AuditFileRole.BUILD_METADATA) return true;
        if (role != AuditFileRole.SECURITY_CONFIGURATION) return false;
        String name = fileName(repositoryPath).toLowerCase(Locale.ROOT);
        return name.matches("(?:application|bootstrap)(?:-[^.]+)?\\.(?:yml|yaml|properties)");
    }

    public static boolean isTestMethodAnnotation(String annotationName) {
        if (annotationName == null || annotationName.isBlank()) return false;
        int separator = annotationName.lastIndexOf('.');
        String simpleName = separator < 0 ? annotationName : annotationName.substring(separator + 1);
        return TEST_METHOD_ANNOTATIONS.contains(simpleName);
    }

    private static boolean isConventionalTestFile(String fileName) {
        if (fileName.endsWith(".java")) {
            String typeName = fileName.substring(0, fileName.length() - ".java".length());
            boolean testPrefix = typeName.length() > 4 && typeName.startsWith("Test")
                    && Character.isUpperCase(typeName.charAt(4));
            return testPrefix || typeName.endsWith("Test") || typeName.endsWith("Tests")
                    || typeName.endsWith("TestCase") || typeName.endsWith("IntegrationTest")
                    || typeName.endsWith("IT");
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        return lower.contains(".test.") || lower.contains(".spec.")
                || lower.startsWith("application-test.")
                || lower.startsWith("application-integrationtest.");
    }

    private static boolean isGeneratedAsset(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return lower.endsWith(".min.js") || lower.endsWith(".bundle.js")
                || lower.endsWith(".min.jsx") || lower.endsWith(".min.ts");
    }

    private static boolean isBuildDescriptor(String lowerName) {
        return lowerName.equals("pom.xml") || lowerName.equals("build.gradle")
                || lowerName.equals("build.gradle.kts") || lowerName.equals("settings.gradle")
                || lowerName.equals("settings.gradle.kts");
    }

    private static boolean isEnvironmentFile(String lowerName) {
        return lowerName.equals(".env") || lowerName.startsWith(".env.");
    }

    private static boolean isDataAccessXml(String lowerPath, String lowerName) {
        return lowerName.endsWith("mapper.xml") || lowerName.contains("mybatis")
                || lowerPath.contains("/mapper/") || lowerPath.contains("/mappers/")
                || lowerPath.contains("/db/changelog/");
    }

    private static boolean isSecurityConfigurationXml(String lowerPath, String lowerName) {
        if (!lowerName.endsWith(".xml")) return false;
        return lowerName.equals("web.xml") || lowerName.startsWith("applicationcontext")
                || lowerName.startsWith("spring-") || lowerName.startsWith("logback")
                || lowerName.startsWith("log4j") || lowerName.contains("security")
                || lowerPath.contains("/meta-inf/") || lowerPath.contains("/web-inf/");
    }

    private static boolean isServerHtmlTemplate(String lowerPath, String lowerName) {
        if (!lowerName.endsWith(".html") && !lowerName.endsWith(".htm")) return false;
        return lowerPath.startsWith("templates/") || lowerPath.contains("/templates/")
                || lowerPath.startsWith("webapp/") || lowerPath.contains("/webapp/")
                || lowerPath.startsWith("web-inf/") || lowerPath.contains("/web-inf/");
    }

    private static String fileName(String repositoryPath) {
        if (repositoryPath == null) return "";
        String normalized = repositoryPath.replace('\\', '/');
        int separator = normalized.lastIndexOf('/');
        return separator < 0 ? normalized : normalized.substring(separator + 1);
    }
}
