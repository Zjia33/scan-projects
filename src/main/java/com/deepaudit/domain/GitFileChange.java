package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class GitFileChange {
    private UUID id;
    private UUID taskId;
    private String oldPath;
    private String newPath;
    private String changeType;
    private int additions;
    private int deletions;
    private String oldRanges;
    private String newRanges;
    private String contextText;
    private boolean configurationChange;

    public GitFileChange(UUID taskId, String oldPath, String newPath, String changeType,
                         int additions, int deletions, String oldRanges, String newRanges,
                         String contextText, boolean configurationChange) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.oldPath = oldPath;
        this.newPath = newPath;
        this.changeType = changeType;
        this.additions = additions;
        this.deletions = deletions;
        this.oldRanges = oldRanges == null ? "" : oldRanges;
        this.newRanges = newRanges == null ? "" : newRanges;
        this.contextText = contextText == null ? "" : contextText;
        this.configurationChange = configurationChange;
    }

}
