package com.deepaudit.source;

public enum AuditFileRole {
    JAVA_SOURCE,
    SECURITY_CONFIGURATION,
    DATA_ACCESS,
    BUILD_METADATA,
    SERVER_TEMPLATE,
    IGNORE;

    public boolean materialize() {
        return this != IGNORE;
    }

    public boolean trackChange() {
        return this != IGNORE;
    }

    public boolean createChunks() {
        return this == JAVA_SOURCE || this == SECURITY_CONFIGURATION
                || this == DATA_ACCESS || this == SERVER_TEMPLATE;
    }

    public boolean inspectForRecon() {
        return this != IGNORE;
    }

    public boolean configurationOrDependency() {
        return this == SECURITY_CONFIGURATION || this == DATA_ACCESS || this == BUILD_METADATA;
    }
}
