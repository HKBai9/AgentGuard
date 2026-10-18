"""Outcome labels shared by reports; never infer benign intent from failed attacks."""


def false_positive(is_benign: bool | None, blocked_count: int) -> bool | None:
    """Task-level benign blocking; unknown labels stay unknown (not zero)."""
    if not isinstance(is_benign, bool):
        return None
    return is_benign and blocked_count > 0
