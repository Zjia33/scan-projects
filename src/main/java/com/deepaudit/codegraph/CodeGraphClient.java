package com.deepaudit.codegraph;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

public interface CodeGraphClient {
    void prepare(UUID taskId, CodeGraphSnapshot snapshot, Path projectRoot);

    List<CodeGraphLocation> impact(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int depth);

    RelatedLocations related(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit);

    void release(UUID taskId);

    record CodeGraphLocation(String name, String kind, String filePath, Integer startLine) {
    }

    record RelatedLocations(List<CodeGraphLocation> callers, List<CodeGraphLocation> callees) {
        // 校验并规范化 RelatedLocations 的构造参数。
        public RelatedLocations {
            callers = callers == null ? List.of() : List.copyOf(callers);
            callees = callees == null ? List.of() : List.copyOf(callees);
        }
    }
}
