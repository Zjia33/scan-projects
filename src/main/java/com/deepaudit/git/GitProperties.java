package com.deepaudit.git;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "deepaudit.git")
public class GitProperties {
    private List<String> allowedHosts = new ArrayList<>(List.of("github.com", "gitlab.com", "gitee.com"));
    private boolean allowLocalRepositories;
    private int transportTimeoutSeconds = 60;
    private int maxCommits = 200;
    private int maxFilesPerSnapshot = 100_000;
    private long maxFileBytes = 10L * 1024L * 1024L;
    private long maxSnapshotBytes = 512L * 1024L * 1024L;

}
