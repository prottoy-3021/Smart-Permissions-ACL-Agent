
from unittest.mock import patch

import pytest

from permission_agent.windows_sid_analysis import (
    analyze_acl_sid_membership,
)


CURRENT_SID = "S-1-5-21-1234-1001"
GROUP_SID = "S-1-5-32-545"
OTHER_SID = "S-1-5-21-5678-2000"


def make_acl(principal, denied=False):
    return {
        "entries": [
            {
                "principal": principal,
                "rights": ["RX"],
                "denied": denied,
                "inherited": True,
            }
        ]
    }


def run_analysis(principal, resolved_sid, enabled):
    with patch(
        "permission_agent.windows_sid_analysis.platform.system",
        return_value="Windows",
    ), patch(
        "permission_agent.windows_sid_analysis._current_user_sid",
        return_value=CURRENT_SID,
    ), patch(
        "permission_agent.windows_sid_analysis._lookup_sid",
        return_value=resolved_sid,
    ), patch(
        "permission_agent.windows_sid_analysis._enabled_membership",
        return_value=enabled,
    ):
        return analyze_acl_sid_membership(
            make_acl(principal)
        )


def test_matches_current_user_sid():
    report = run_analysis(
        r"PROTTOY\prott",
        CURRENT_SID,
        False,
    )

    assert report["current_user_match_count"] == 1
    assert report["entries"][0]["match"] == "CURRENT_USER"


def test_matches_enabled_group():
    report = run_analysis(
        r"BUILTIN\Users",
        GROUP_SID,
        True,
    )

    assert report["enabled_group_match_count"] == 1
    assert report["entries"][0]["match"] == "ENABLED_GROUP"


def test_nonmember_not_confirmed():
    report = run_analysis(
        r"EXAMPLE\OtherGroup",
        OTHER_SID,
        False,
    )

    assert report["entries"][0]["match"] == "NOT_CONFIRMED"
    assert report["entries"][0]["enabled_for_allow"] is False


def test_unresolved_principal():
    with patch(
        "permission_agent.windows_sid_analysis.platform.system",
        return_value="Windows",
    ), patch(
        "permission_agent.windows_sid_analysis._current_user_sid",
        return_value=CURRENT_SID,
    ), patch(
        "permission_agent.windows_sid_analysis._lookup_sid",
        side_effect=OSError("Unknown account"),
    ):
        report = analyze_acl_sid_membership(
            make_acl("UnknownAccount")
        )

    assert report["unresolved_count"] == 1
    assert report["policy_verified"] is False


def test_reject_linux():
    with patch(
        "permission_agent.windows_sid_analysis.platform.system",
        return_value="Linux",
    ):
        with pytest.raises(RuntimeError):
            analyze_acl_sid_membership(
                make_acl("test")
            )


def test_never_claim_effective_access():
    report = run_analysis(
        r"BUILTIN\Users",
        GROUP_SID,
        True,
    )

    assert report["effective_access_verified"] is False
    assert report["policy_verified"] is False
    assert report["permissions_changed"] is False
