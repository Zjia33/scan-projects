package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Collapses only obvious proposal duplicates before the Critic model call.
 * Final authoritative deduplication still happens after Critic relocation.
 */
public final class AgentCandidateConsolidator {

    private AgentCandidateConsolidator() {
    }

    public static List<AgentCandidate> consolidate(List<AgentCandidate> candidates) {
        List<AgentCandidate> consolidated = new ArrayList<>();
        if (candidates == null) return consolidated;
        for (AgentCandidate candidate : candidates) {
            if (candidate == null || candidate.proposal() == null) continue;
            consolidated.add(candidate);
        }
        collapseOverlaps(consolidated);
        return consolidated;
    }

    private static void collapseOverlaps(List<AgentCandidate> consolidated) {
        boolean merged;
        do {
            merged = false;
            outer:
            for (int left = 0; left < consolidated.size(); left++) {
                for (int right = left + 1; right < consolidated.size(); right++) {
                    if (!sameProposedLocation(
                            consolidated.get(left).proposal(), consolidated.get(right).proposal())) {
                        continue;
                    }
                    consolidated.set(left, merge(consolidated.get(left), consolidated.remove(right)));
                    merged = true;
                    break outer;
                }
            }
        } while (merged);
    }

    private static boolean sameProposedLocation(LlmGateway.FindingProposal left,
                                                LlmGateway.FindingProposal right) {
        if (left.type() != right.type() || !Objects.equals(left.primaryChunkId(), right.primaryChunkId())) {
            return false;
        }
        Integer leftStart = left.vulnerabilityStartLine();
        Integer leftEnd = left.vulnerabilityEndLine();
        Integer rightStart = right.vulnerabilityStartLine();
        Integer rightEnd = right.vulnerabilityEndLine();
        if (leftStart == null || leftEnd == null || rightStart == null || rightEnd == null) return false;
        return leftStart <= rightEnd && rightStart <= leftEnd;
    }

    private static AgentCandidate merge(AgentCandidate left, AgentCandidate right) {
        AgentCandidate preferred = prefer(left, right);
        LlmGateway.FindingProposal first = left.proposal();
        LlmGateway.FindingProposal second = right.proposal();
        Set<Long> evidenceIds = new LinkedHashSet<>();
        evidenceIds.add(first.primaryChunkId());
        evidenceIds.addAll(first.evidenceChunkIds());
        evidenceIds.addAll(second.evidenceChunkIds());
        evidenceIds.remove(null);

        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                first.type(),
                stronger(first.severity(), second.severity()),
                stronger(first.confidence(), second.confidence()),
                specific(first.title(), second.title()),
                specific(first.description(), second.description()),
                specific(first.remediation(), second.remediation()),
                first.primaryChunkId(),
                new ArrayList<>(evidenceIds),
                Math.min(first.vulnerabilityStartLine(), second.vulnerabilityStartLine()),
                Math.max(first.vulnerabilityEndLine(), second.vulnerabilityEndLine()));
        return new AgentCandidate(preferred.sourceAgent(), proposal,
                mergeText(left.evidence(), right.evidence()), preferred.hypothesis());
    }

    private static AgentCandidate prefer(AgentCandidate left, AgentCandidate right) {
        int leftScore = informationScore(left.proposal());
        int rightScore = informationScore(right.proposal());
        return rightScore > leftScore ? right : left;
    }

    private static int informationScore(LlmGateway.FindingProposal proposal) {
        return textLength(proposal.title()) + textLength(proposal.description())
                + textLength(proposal.remediation()) + proposal.evidenceChunkIds().size() * 100;
    }

    private static Severity stronger(Severity left, Severity right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.ordinal() <= right.ordinal() ? left : right;
    }

    private static Confidence stronger(Confidence left, Confidence right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.ordinal() <= right.ordinal() ? left : right;
    }

    private static String specific(String left, String right) {
        String first = left == null ? "" : left.strip();
        String second = right == null ? "" : right.strip();
        if (first.length() != second.length()) return first.length() > second.length() ? first : second;
        return first.compareTo(second) <= 0 ? first : second;
    }

    private static String mergeText(String left, String right) {
        String first = left == null ? "" : left.strip();
        String second = right == null ? "" : right.strip();
        if (first.isBlank()) return second;
        if (second.isBlank() || first.equals(second)) return first;
        return first + "\n\n---\n\n" + second;
    }

    private static int textLength(String value) {
        return value == null ? 0 : value.strip().length();
    }
}
