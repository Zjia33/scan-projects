package com.deepaudit.semantic;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "deepaudit.semantic")
public class SemanticAnalysisProperties {
    private boolean enabled = true;
    private int maxCallDepth = 10;
    private int maxPathsPerEntry = 20;
    private int maxStatesPerEntry = 1000;

    public boolean isEnabled() { return enabled; }
    public int getMaxCallDepth() { return maxCallDepth; }
    public int getMaxPathsPerEntry() { return maxPathsPerEntry; }
    public int getMaxStatesPerEntry() { return maxStatesPerEntry; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public void setMaxCallDepth(int maxCallDepth) { this.maxCallDepth = maxCallDepth; }
    public void setMaxPathsPerEntry(int maxPathsPerEntry) { this.maxPathsPerEntry = maxPathsPerEntry; }
    public void setMaxStatesPerEntry(int maxStatesPerEntry) { this.maxStatesPerEntry = maxStatesPerEntry; }
}
