package com.deepaudit.codegraph;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

// 定义 CodeGraphClient 的协作接口和能力边界。
public interface CodeGraphClient {
    // 执行 CodeGraphClient 中的 prepare 处理。
    void prepare(UUID taskId, CodeGraphSnapshot snapshot, Path projectRoot);

    // 执行 CodeGraphClient 中的 impact 处理。
    List<CodeGraphLocation> impact(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int depth);

    // 执行 CodeGraphClient 中的 related 处理。
    RelatedLocations related(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit);

    // 执行 CodeGraphClient 中的 release 处理。
    void release(UUID taskId);

    // 封装 CodeGraphLocation 使用的不可变结构化数据。
    record CodeGraphLocation(String name, String kind, String filePath, Integer startLine) {
    }

    // 封装 RelatedLocations 使用的不可变结构化数据。
    record RelatedLocations(List<CodeGraphLocation> callers, List<CodeGraphLocation> callees) {
        // 校验并规范化 RelatedLocations 的构造参数。
        public RelatedLocations {
            callers = callers == null ? List.of() : List.copyOf(callers);
            callees = callees == null ? List.of() : List.copyOf(callees);
        }
    }
}
