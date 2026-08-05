package com.deepaudit.codegraph;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

public interface CodeGraphClient {
    void prepare(UUID taskId, Path projectRoot);

    RelatedLocations related(UUID taskId, String symbol, int limit);

    void release(UUID taskId);

    record CodeGraphLocation(String name, String kind, String filePath, Integer startLine) {
    }

    record RelatedLocations(List<CodeGraphLocation> callers, List<CodeGraphLocation> callees,
                            boolean callersTruncated, boolean calleesTruncated) {
        // 校验并规范化 RelatedLocations 的构造参数。
        public RelatedLocations {
            callers = callers == null ? List.of() : List.copyOf(callers);
            callees = callees == null ? List.of() : List.copyOf(callees);
        }

        public RelatedLocations(List<CodeGraphLocation> callers, List<CodeGraphLocation> callees) {
            this(callers, callees, false, false);
        }
    }
}
