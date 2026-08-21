package com.deepaudit.git;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UnifiedChangeContextTest {

    @Test
    void mergesNearbyEditsAndKeepsBothEndsOfAShortMethod() {
        String base = "oldHead();\nline2();\nline3();\nline4();\noldTail();";
        String target = "newHead();\nline2();\nline3();\nline4();\nnewTail();";

        String context = UnifiedChangeContext.render(
                base, target, null, 100, 5, 12_000, true);

        assertThat(context).containsOnlyOnce("@@ base")
                .contains("- B1 | oldHead();", "+ T100 | newHead();",
                        "  T101 | line2();", "- B5 | oldTail();", "+ T104 | newTail();");
    }
}
