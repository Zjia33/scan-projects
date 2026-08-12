package com.deepaudit.codegraph;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

public interface CodeGraphClient {
    void prepare(UUID taskId, CodeGraphSnapshot snapshot, Path projectRoot);

    List<CodeGraphLocation> impact(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int depth);

    List<CodeGraphLocation> query(UUID taskId, CodeGraphSnapshot snapshot,
                                  String search, String kind, int limit);

    List<CodeGraphLocation> callers(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit);

    List<CodeGraphLocation> callees(UUID taskId, CodeGraphSnapshot snapshot, String symbol, int limit);

    void release(UUID taskId);

    record CodeGraphLocation(String name, String kind, String filePath, Integer startLine) {
    }

}
