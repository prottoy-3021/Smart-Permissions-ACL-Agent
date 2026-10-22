
from permission_agent.windows_token_analysis import (
    analyze_token_acl_overlap,
)


IDENTITY = {
    "inspection_status": "COMPLETED",
    "current_user": {
        "username": r"PROTTOY\prott",
        "sid": "S-1-5-21-1234-1001",
    },
    "groups": [
        {
            "group_name": r"BUILTIN\Users",
            "sid": "S-1-5-32-545",
            "attributes": "Enabled group",
        },
        {
            "group_name": r"BUILTIN\Administrators",
            "sid": "S-1-5-32-544",
            "attributes": "Group used for deny only",
        },
        {
            "group_name": r"EXAMPLE\Disabled",
            "sid": "S-1-5-21-1234-2000",
            "attributes": "Mandatory group",
        },
    ],
}


def make_acl(principal, denied=False, rights=None):
    return {
        "entries": [
            {
                "principal": principal,
                "rights": rights or ["RX"],
                "denied": denied,
                "inherited": True,
            }
        ]
    }


def test_current_user_acl_match():
    report = analyze_token_acl_overlap(
        make_acl(r"PROTTOY\prott"),
        IDENTITY,
    )

    assert report["allow_candidate_count"] == 1
    assert report["allow_candidates"][0][
        "matched_as"
    ] == "CURRENT_USER"


def test_enabled_group_acl_match():
    report = analyze_token_acl_overlap(
        make_acl(r"BUILTIN\Users"),
        IDENTITY,
    )

    assert report["allow_candidate_count"] == 1
    assert report["deny_candidate_count"] == 0


def test_deny_only_group_cannot_grant_access():
    report = analyze_token_acl_overlap(
        make_acl(
            r"BUILTIN\Administrators",
            rights=["F"],
        ),
        IDENTITY,
    )

    assert report["allow_candidate_count"] == 0
    assert len(
        report["inactive_group_matches"]
    ) == 1


def test_deny_only_group_matches_deny_entry():
    report = analyze_token_acl_overlap(
        make_acl(
            r"BUILTIN\Administrators",
            denied=True,
            rights=["W"],
        ),
        IDENTITY,
    )

    assert report["deny_candidate_count"] == 1


def test_disabled_group_not_counted_as_allow():
    report = analyze_token_acl_overlap(
        make_acl(r"EXAMPLE\Disabled"),
        IDENTITY,
    )

    assert report["allow_candidate_count"] == 0
    assert len(
        report["inactive_group_matches"]
    ) == 1


def test_unrelated_principal_not_matched():
    report = analyze_token_acl_overlap(
        make_acl(r"EXAMPLE\AnotherUser"),
        IDENTITY,
    )

    assert report["allow_candidate_count"] == 0
    assert report["deny_candidate_count"] == 0


def test_incomplete_identity_report():
    report = analyze_token_acl_overlap(
        make_acl(r"BUILTIN\Users"),
        {
            "inspection_status": "FAILED",
        },
    )

    assert report["analysis_status"] == "UNAVAILABLE"
    assert report["effective_access_verified"] is False


def test_analysis_never_claims_effective_access():
    report = analyze_token_acl_overlap(
        make_acl(r"PROTTOY\prott"),
        IDENTITY,
    )

    assert report["policy_verified"] is False
    assert report["effective_access_verified"] is False
    assert report["permissions_changed"] is False
