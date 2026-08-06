package com.deepaudit.codegraph;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

public interface CodeGraphClient {
    void prepare(UUID taskId, Path projectRoot);

    RelationLocations callers(UUID taskId, String symbol, int limit);

    RelationLocations callees(UUID taskId, String symbol, int limit);

    void release(UUID taskId);

    record CodeGraphLocation(String name, String kind, String filePath, Integer startLine) {
    }

    record RelationLocations(List<CodeGraphLocation> locations, boolean truncated) {
        public RelationLocations {
            locations = locations == null ? List.of() : List.copyOf(locations);
        }
    }
}
