package com.deepaudit.recon;

import java.util.List;

/**
 * 由完整目标快照确定性生成的项目结构画像。画像只包含聚合统计和代码位置，不包含业务源码正文。
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

    // 执行 ProjectStructureProfile 中的 empty 处理。
    public static ProjectStructureProfile empty() {
        return new ProjectStructureProfile(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of());
    }

    // 执行 ProjectStructureProfile 中的 immutable 处理。
    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    // 封装 ModuleProfile 使用的不可变结构化数据。
    public record ModuleProfile(String path, int sourceFileCount, int javaMethodCount,
                                int endpointCount, int changedChunkCount, int impactedChunkCount) {
    }

    // 封装 LayerProfile 使用的不可变结构化数据。
    public record LayerProfile(String module, String layer, int sourceFileCount, int codeChunkCount) {
    }

    /**
     * occurrenceCount 统计完整项目中的全部命中；evidence 只保留有限个位置示例以约束模型上下文。
     */
    public record FactGroup(String module, String kind, int occurrenceCount, List<String> evidence) {
        // 校验并规范化 FactGroup 的构造参数。
        public FactGroup {
            evidence = immutable(evidence);
        }
    }
}
