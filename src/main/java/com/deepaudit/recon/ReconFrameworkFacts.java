package com.deepaudit.recon;

import java.util.List;

/**
 * Recon 模型的最小输入契约。只保留框架、模块、分层和组件类别，不携带代码量、命中次数或增量作用域。
 */
public record ReconFrameworkFacts(FrameworkTechnology technology,
                                  List<String> modules,
                                  List<ModuleLayer> layers,
                                  List<String> entryPointTypes,
                                  List<String> securityComponentTypes,
                                  List<String> dataAccessTypes,
                                  List<String> integrationTypes,
                                  List<ReconFrameworkFile> frameworkFiles) {

    public static ReconFrameworkFacts from(ReconSummary summary) {
        ProjectStructureProfile structure = summary.projectStructure();
        return new ReconFrameworkFacts(
                FrameworkTechnology.from(summary.technologyProfile()),
                structure.modules().stream().map(ProjectStructureProfile.ModuleProfile::path).distinct().toList(),
                structure.layers().stream()
                        .map(layer -> new ModuleLayer(layer.module(), layer.layer())).distinct().toList(),
                kinds(structure.entryPoints()), kinds(structure.securityMechanisms()),
                kinds(structure.dataAccess()), kinds(structure.externalIntegrations()),
                summary.frameworkFiles());
    }

    private static List<String> kinds(List<ProjectStructureProfile.FactGroup> facts) {
        return facts.stream().map(ProjectStructureProfile.FactGroup::kind).distinct().sorted().toList();
    }

    public record ModuleLayer(String module, String layer) {
    }

    public record FrameworkTechnology(List<String> frameworks,
                                      List<String> securityFrameworks,
                                      List<String> persistenceFrameworks,
                                      List<String> buildTools) {
        private static FrameworkTechnology from(TechnologyProfile profile) {
            return new FrameworkTechnology(profile.frameworks(), profile.securityFrameworks(),
                    profile.persistenceFrameworks(), profile.buildTools());
        }
    }
}
