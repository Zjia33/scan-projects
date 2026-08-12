package com.deepaudit.domain;

/**
 * Describes whether the primary report location is an implemented root cause or the operation
 * responsible for enforcing a control that is completely absent from source code.
 */
public enum FindingLocationKind {
    ROOT_CAUSE,
    RESPONSIBILITY_ANCHOR,
    UNCLASSIFIED
}
