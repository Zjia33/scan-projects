package com.deepaudit.recon;

// 源文件数量、Java方法数量、Java 接口端点数量，以及确定性技术栈和项目结构事实。
public record ReconSummary(int sourceFileCount, int javaMethodCount, int endpointCount, int chunkCount,
                           TechnologyProfile technologyProfile,
                           ProjectStructureProfile projectStructure) {
    // 校验并规范化 ReconSummary 的构造参数。
    public ReconSummary {
        technologyProfile = technologyProfile == null ? TechnologyProfile.empty() : technologyProfile;
        projectStructure = projectStructure == null ? ProjectStructureProfile.empty() : projectStructure;
    }

    // 创建 ReconSummary 实例并初始化所需依赖或状态。
    public ReconSummary(int sourceFileCount, int javaMethodCount, int endpointCount, int chunkCount,
                        TechnologyProfile technologyProfile) {
        this(sourceFileCount, javaMethodCount, endpointCount, chunkCount,
                technologyProfile, ProjectStructureProfile.empty());
    }

    // 创建 ReconSummary 实例并初始化所需依赖或状态。
    public ReconSummary(int sourceFileCount, int javaMethodCount, int endpointCount, int chunkCount) {
        this(sourceFileCount, javaMethodCount, endpointCount, chunkCount,
                TechnologyProfile.empty(), ProjectStructureProfile.empty());
    }
}
