package com.deepaudit.source;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

/**
 * Defines repository paths that belong to the auditable production source set.
 */
public final class AuditSourceFilter {
    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of(
            ".git", ".github", ".idea", ".vscode", ".gradle",
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

    public static boolean shouldAnalyze(Path root, Path candidate) {
        if (root == null || candidate == null) return false;
        try {
            return shouldAnalyze(root.toAbsolutePath().normalize()
                    .relativize(candidate.toAbsolutePath().normalize()).toString());
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    public static boolean shouldAnalyze(String repositoryPath) {
        if (repositoryPath == null) return false;
        String normalized = repositoryPath.replace('\\', '/');
        while (normalized.startsWith("./")) normalized = normalized.substring(2);
        while (normalized.contains("//")) normalized = normalized.replace("//", "/");
        if (normalized.isBlank()) return true;

        String[] segments = normalized.split("/");
        for (String segment : segments) {
            if (EXCLUDED_DIRECTORIES.contains(segment.toLowerCase(Locale.ROOT))) return false;
        }
        String fileName = segments[segments.length - 1];
        return !isConventionalTestFile(fileName) && !isGeneratedAsset(fileName);
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
}
