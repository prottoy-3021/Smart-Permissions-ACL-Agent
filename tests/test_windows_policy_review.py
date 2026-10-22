
from permission_agent.windows_policy_review import (
    review_windows_policy,
)


TARGET = "S-1-5-21-1000-2000"
OTHER = "S-1-5-32-545"
SYSTEM = "S-1-5-18"


def ace(
    sid,
    mask="0x2",
    ace_type="ALLOW",
    inherited=False,
    inherit_only=False,
):
    return {
        "sid": sid,
        "mask": mask,
        "type": ace_type,
        "inherited": inherited,
        "inherit_only": inherit_only,
    }


def report(entries=None, null_dacl=False):
    return {
        "inspection_status": "COMPLETED",
        "null_dacl": null_dacl,
        "entries": entries or [],
    }


def review(entries, **kwargs):
    return review_windows_policy(
        report(entries),
        target_sid=TARGET,
        **kwargs,
    )


def test_target_write_entry_detected():
    result = review([ace(TARGET)])

    assert len(result["target_write_entries"]) == 1


def test_other_write_entry_detected():
    result = review([ace(OTHER)])

    assert len(result["other_write_entries"]) == 1


def test_explicit_exception_classified():
    result = review(
        [ace(SYSTEM)],
        approved_writer_sids=[SYSTEM],
    )

    assert len(result["exception_write_entries"]) == 1
    assert result["policy_verified"] is False


def test_privileged_not_exempt_by_default():
    result = review([ace(SYSTEM)])

    assert len(result["privileged_entries"]) == 1
    assert len(result["other_write_entries"]) == 1


def test_read_only_entry_not_flagged_as_write():
    result = review([ace(OTHER, "0x21")])

    assert len(result["other_write_entries"]) == 0


def test_inherit_only_requires_child_review():
    result = review([
        ace(OTHER, inherit_only=True)
    ])

    assert len(result["other_write_entries"]) == 0
    assert any(
        "child-object" in text
        for text in result["findings"]
    )


def test_deny_entry_counted():
    result = review([
        ace(OTHER, ace_type="DENY")
    ])

    assert result["deny_entry_count"] == 1


def test_null_dacl_is_not_ready():
    result = review_windows_policy(
        report(null_dacl=True),
        target_sid=TARGET,
    )

    assert result["ready_to_apply"] is False
    assert result["review_status"] == "INCOMPLETE_EVIDENCE"


def test_incomplete_inspection():
    result = review_windows_policy(
        {"inspection_status": "FAILED"},
        target_sid=TARGET,
    )

    assert result["review_status"] == "INCOMPLETE_EVIDENCE"


def test_policy_never_claims_verification():
    result = review([ace(TARGET, "0x21")])

    assert result["ready_to_apply"] is False
    assert result["effective_access_verified"] is False
    assert result["policy_verified"] is False
    assert result["permissions_changed"] is False
