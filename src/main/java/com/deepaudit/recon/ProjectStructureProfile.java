package com.deepaudit.recon;

import java.util.List;

/**
 * 由完整目标快照确定性生成的项目结构画像。画像只包含整体模块、分层和事实计数。
 */
public record ProjectStructureProfile(List<ModuleProfile> modules,
                                      List<LayerProfile> layers,
                                      List<FactGroup> entryPoints,
                                      List<FactGroup> securityMechanisms,
                                      List<FactGroup> dataAccess,
                                      List<FactGroup> externalIntegrations,
                                      List<FactGroup> configurationFiles) {

    // 校验并规范化 ProjectStructureProfile 的构造参数。
    public ProjectStructureProfile {
        modules = immutable(modules);
        layers = immutable(layers);
        entryPoints = immutable(entryPoints);
        securityMechanisms = immutable(securityMechanisms);
        dataAccess = immutable(dataAccess);
        externalIntegrations = immutable(externalIntegrations);
        configurationFiles = immutable(configurationFiles);
    }

    public static ProjectStructureProfile empty() {
        return new ProjectStructureProfile(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of());
    }

    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    public record ModuleProfile(String path, int sourceFileCount, int javaMethodCount,
                                int endpointCount, int changedChunkCount, int impactedChunkCount) {
    }

    public record LayerProfile(String module, String layer, int sourceFileCount, int codeChunkCount) {
    }

    // 按模块和事实类别保存完整项目中的命中数量，不携带文件、方法或代码位置。
    public record FactGroup(String module, String kind, int occurrenceCount) {
    }
}
