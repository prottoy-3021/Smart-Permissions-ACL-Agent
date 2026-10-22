
from permission_agent.windows_policy_audit import (
    audit_read_only_policy,
)


TARGET_SID = "S-1-5-21-1000-2000"
OTHER_SID = "S-1-5-32-545"


def make_ace(
    sid,
    mask,
    ace_type="ALLOW",
    inherited=False,
    inherit_only=False,
):
    return {
        "type": ace_type,
        "sid": sid,
        "mask": hex(mask),
        "inherited": inherited,
        "inherit_only": inherit_only,
    }


def make_report(entries=None, null_dacl=False):
    if entries is None:
        entries = []

    return {
        "inspection_status": "COMPLETED",
        "null_dacl": null_dacl,
        "entries": entries,
    }


def audit(entries, null_dacl=False, target_sid=TARGET_SID):
    return audit_read_only_policy(
        make_report(entries, null_dacl),
        target_principal="IIS_IUSRS",
        target_sid=target_sid,
    )


def finding_codes(report):
    return {
        item["code"]
        for item in report["findings"]
    }


def test_target_read_execute_candidate():
    report = audit([
        make_ace(TARGET_SID, 0x21)
    ])

    assert report["target_rx_candidate_count"] == 1
    assert report["assessment"] == "UNVERIFIED"
    assert report["policy_verified"] is False


def test_missing_target_read_execute():
    report = audit([
        make_ace(OTHER_SID, 0x21)
    ])

    assert report["target_rx_candidate_count"] == 0
    assert (
        "NO_DIRECT_TARGET_RX_CANDIDATE"
        in finding_codes(report)
    )


def test_detect_target_excessive_rights():
    report = audit([
        make_ace(TARGET_SID, 0x23)
    ])

    assert (
        "TARGET_EXCESSIVE_RIGHTS"
        in finding_codes(report)
    )


def test_detect_other_write_grant():
    report = audit([
        make_ace(TARGET_SID, 0x21),
        make_ace(OTHER_SID, 0x02),
    ])

    assert report["potential_write_grant_count"] == 1
    assert (
        "OTHER_WRITE_GRANT_REVIEW"
        in finding_codes(report)
    )


def test_privileged_account_requires_review():
    report = audit([
        make_ace(TARGET_SID, 0x21),
        make_ace("S-1-5-18", 0x1F01FF),
    ])

    assert (
        "PRIVILEGED_EXCEPTION_REVIEW"
        in finding_codes(report)
    )


def test_inherited_entry_is_counted():
    report = audit([
        make_ace(
            TARGET_SID,
            0x21,
            inherited=True,
        )
    ])

    assert report["inherited_entry_count"] == 1


def test_inherit_only_grant_not_counted():
    report = audit([
        make_ace(
            OTHER_SID,
            0x02,
            inherit_only=True,
        )
    ])

    assert report["potential_write_grant_count"] == 0


def test_detect_target_deny_entry():
    report = audit([
        make_ace(
            TARGET_SID,
            0x01,
            ace_type="DENY",
        )
    ])

    assert report["deny_entry_count"] == 1
    assert (
        "TARGET_DENY_REVIEW"
        in finding_codes(report)
    )


def test_null_dacl_is_critical():
    report = audit(
        [],
        null_dacl=True,
    )

    assert "NULL_DACL" in finding_codes(report)
    assert report["policy_verified"] is False


def test_empty_dacl_is_flagged():
    report = audit([])

    assert "EMPTY_DACL" in finding_codes(report)


def test_unresolved_target_sid():
    report = audit([
        make_ace(OTHER_SID, 0x02)
    ], target_sid=None)

    assert (
        "TARGET_SID_UNRESOLVED"
        in finding_codes(report)
    )


def test_audit_never_changes_permissions():
    report = audit([
        make_ace(TARGET_SID, 0x21)
    ])

    assert report["permissions_changed"] is False
    assert report["effective_access_verified"] is False
    assert report["policy_verified"] is False
