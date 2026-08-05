package com.deepaudit.source;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class AuditSourceFilterTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "src/test/java/demo/OrderServiceTest.java",
            "src/test/resources/application.yml",
            "src/integrationTest/java/demo/OrderIT.java",
            "tests/security/order.spec.js",
            "module/__tests__/order.test.ts",
            "target/generated-sources/demo/Generated.java",
            "build/generated/demo/Generated.java",
            "node_modules/library/index.js",
            "vendor/library/client.js",
            ".github/workflows/build.yml",
            "docs/examples/InsecureExample.java",
            "src/main/resources/static/vendor.bundle.js",
            "README.md",
            "CHANGELOG.md",
            "frontend/src/order.ts",
            "frontend/src/OrderView.vue",
            "src/main/resources/static/app.js",
            "src/main/resources/static/styles.css",
            "src/main/resources/static/index.html",
            "src/main/resources/data/catalog.xml",
            "package.json",
            "package-lock.json"
    })
    void classifiesTestsGeneratedDependenciesDocumentationAndFrontendAsIgnored(String path) {
        assertThat(AuditSourceFilter.classify(path)).isEqualTo(AuditFileRole.IGNORE);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "src/main/java/demo/OrderService.java",
            "src/main/java/demo/Contest.java",
            "src/main/java/demo/Audit.java"
    })
    void classifiesProductionJavaSources(String path) {
        assertThat(AuditSourceFilter.classify(path)).isEqualTo(AuditFileRole.JAVA_SOURCE);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "src/main/resources/application.yml",
            "src/main/resources/application-prod.properties",
            "src/main/resources/custom-security.yaml",
            ".env.production"
    })
    void classifiesRuntimeConfiguration(String path) {
        assertThat(AuditSourceFilter.classify(path)).isEqualTo(AuditFileRole.SECURITY_CONFIGURATION);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "src/main/resources/mapper/OrderMapper.xml",
            "src/main/resources/mappers/query.xml",
            "src/main/resources/db/migration/V1__schema.sql"
    })
    void classifiesDataAccessResources(String path) {
        assertThat(AuditSourceFilter.classify(path)).isEqualTo(AuditFileRole.DATA_ACCESS);
    }

    @ParameterizedTest
    @ValueSource(strings = {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle.kts"})
    void classifiesJavaBuildMetadataWithoutCreatingChunks(String path) {
        AuditFileRole role = AuditSourceFilter.classify(path);

        assertThat(role).isEqualTo(AuditFileRole.BUILD_METADATA);
        assertThat(role.materialize()).isTrue();
        assertThat(role.trackChange()).isTrue();
        assertThat(role.inspectForRecon()).isTrue();
        assertThat(role.createChunks()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "src/main/resources/templates/order.html",
            "templates/order.html",
            "src/main/webapp/WEB-INF/views/order.jsp",
            "src/main/resources/templates/mail.ftl"
    })
    void keepsOnlyServerRenderedTemplates(String path) {
        assertThat(AuditSourceFilter.classify(path)).isEqualTo(AuditFileRole.SERVER_TEMPLATE);
    }

    @Test
    void handlesNullAndPathsOutsideRootAsIgnored() {
        assertThat(AuditSourceFilter.classify((String) null)).isEqualTo(AuditFileRole.IGNORE);
        assertThatNoException().isThrownBy(() -> AuditSourceFilter.classify(null, null));
        assertThat(AuditSourceFilter.classify(null, null)).isEqualTo(AuditFileRole.IGNORE);
    }

    @Test
    void recognizesJUnitAndTestNgMethodAnnotations() {
        assertThat(AuditSourceFilter.isTestMethodAnnotation("Test")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("org.junit.jupiter.api.ParameterizedTest")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("BeforeMethod")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("Transactional")).isFalse();
    }
}
