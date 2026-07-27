package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class GitFileChange {
    private UUID id; // 文件变更记录的唯一标识
    private UUID taskId; // 变更记录所属的增量审计任务 ID
    private String oldPath; // 文件在基线提交中的相对路径
    private String newPath; // 文件在目标提交中的相对路径
    private String changeType; // Git 文件变更类型，如新增、修改、重命名或删除
    private int additions; // 差异中新增的行数
    private int deletions; // 差异中删除的行数
    private String oldRanges; // 基线文件受影响行区间的序列化文本
    private String newRanges; // 目标文件受影响行区间的序列化文本
    private String contextText; // 供增量分析使用的统一差异上下文
    private boolean configurationChange; // 是否属于需整体纳入分析的配置文件变更

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
