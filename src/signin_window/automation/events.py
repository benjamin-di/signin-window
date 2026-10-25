"""Closed challenge outcome vocabulary; no site or account data."""

from enum import StrEnum


class HCaptchaPromptFamily(StrEnum):
    LINE = "line"
    SHAPE = "shape"
    PATTERN = "pattern"
    SEMANTIC_GRID = "semantic_grid"
    ANIMAL_COUNT = "animal_count"
    MOTION = "motion"
    DRAG = "drag"
    OTHER = "other"


class HCaptchaPlanKind(StrEnum):
    GRID = "grid"
    POINT = "point"
    DRAG = "drag"
    PASS = "pass"  # noqa: S105 -- an action kind, never a credential


class HCaptchaVendorOutcome(StrEnum):
    NOT_OBSERVED = "not_observed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class HCaptchaTerminalReason(StrEnum):
    NATIVE_ACCEPTED = "native_accepted"
    PLANNER_DECLINED = "planner_declined"
    CORRECTIVE_REPEAT = "corrective_repeat"
    UNCHANGED_AFTER_CORRECTION = "unchanged_after_correction"
    ROUND_BUDGET_EXHAUSTED = "round_budget_exhausted"
    STALE_PLAN = "stale_plan"
    WALL_BUDGET_EXHAUSTED = "wall_budget_exhausted"


class HCaptchaAttemptTerminalReason(StrEnum):
    TASK_IDENTITY_UNAVAILABLE = "task_identity_unavailable"
    ACCEPTED = "accepted"
    PLANNER_DECLINED = "planner_declined"
    PLANNER_FAILED = "planner_failed"
    ACTION_FAILED = "action_failed"
    SURFACE_MISSING = "surface_missing"
    WALL_BUDGET_EXHAUSTED = "wall_budget_exhausted"
    ROUND_BUDGET_EXHAUSTED = "round_budget_exhausted"
    UNCHANGED_AFTER_CORRECTION = "unchanged_after_correction"
    STALE_PLAN = "stale_plan"


class HCaptchaSurfaceMissBucket(StrEnum):
    NONE = "none"
    ONE = "one"
    TWO = "two"
    THREE_OR_MORE = "three_or_more"
