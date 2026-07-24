package com.deepaudit.source;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

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
            "src/main/resources/static/vendor.bundle.js"
    })
    void excludesTestsGeneratedCodeDependenciesAndDocumentation(String path) {
        assertThat(AuditSourceFilter.shouldAnalyze(path)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "pom.xml",
            "src/main/java/demo/OrderService.java",
            "src/main/java/demo/Contest.java",
            "src/main/java/demo/Audit.java",
            "src/main/resources/application.yml",
            "src/main/resources/mapper/OrderMapper.xml",
            "src/main/resources/db/migration/V1__schema.sql",
            "frontend/src/order.ts"
    })
    void keepsProductionSourceAndSecurityRelevantConfiguration(String path) {
        assertThat(AuditSourceFilter.shouldAnalyze(path)).isTrue();
    }

    @Test
    void recognizesJUnitAndTestNgMethodAnnotations() {
        assertThat(AuditSourceFilter.isTestMethodAnnotation("Test")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("org.junit.jupiter.api.ParameterizedTest")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("BeforeMethod")).isTrue();
        assertThat(AuditSourceFilter.isTestMethodAnnotation("Transactional")).isFalse();
    }
}
