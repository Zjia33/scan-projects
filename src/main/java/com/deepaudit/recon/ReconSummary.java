package com.deepaudit.recon;

// 源文件数量、Java方法数量、Java 接口端点数量和确定性技术栈事实。
public record ReconSummary(int sourceFileCount, int javaMethodCount, int endpointCount, int chunkCount,
                           TechnologyProfile technologyProfile) {
    public ReconSummary {
        technologyProfile = technologyProfile == null ? TechnologyProfile.empty() : technologyProfile;
    }

    public ReconSummary(int sourceFileCount, int javaMethodCount, int endpointCount, int chunkCount) {
        this(sourceFileCount, javaMethodCount, endpointCount, chunkCount, TechnologyProfile.empty());
    }
}
