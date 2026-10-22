
"""
Windows token and ACL matching.

This module compares visible ACL principals with the
current process user and group information.

It does not calculate Windows effective access.
It never modifies permissions.
"""


def _normalize(value):
    """Normalize account names and SID strings."""
    return str(value or "").strip().casefold()


def _group_state(attributes):
    """
    Identify whether a group can participate in
    ordinary allow matching or deny matching.

    A deny-only group cannot grant access.
    """
    flags = _normalize(attributes)

    deny_only = "deny only" in flags

    enabled = (
        "enabled group" in flags
        and not deny_only
    )

    return {
        "enabled_for_allow": enabled,
        "enabled_for_deny": enabled or deny_only,
        "deny_only": deny_only,
    }


def analyze_token_acl_overlap(acl_report, identity_report):
    """
    Match visible ACL entries against the current
    Windows process identity.

    Returns matching allow and deny candidates.

    This is not an AuthzAccessCheck implementation.
    It does not resolve effective access.
    """

    if (
        identity_report.get("inspection_status")
        != "COMPLETED"
    ):
        return {
            "analysis_status": "UNAVAILABLE",
            "reason": "Windows identity inspection is incomplete.",
            "effective_access_verified": False,
            "permissions_changed": False,
        }

    current_user = identity_report.get(
        "current_user", {}
    )

    user_identifiers = {
        _normalize(current_user.get("username")),
        _normalize(current_user.get("sid")),
    }

    user_identifiers.discard("")

    groups = {}

    for group in identity_report.get("groups", []):
        state = _group_state(
            group.get("attributes", "")
        )

        for identifier in (
            group.get("group_name"),
            group.get("sid"),
        ):
            key = _normalize(identifier)

            if key:
                groups[key] = {
                    "group_name": group.get(
                        "group_name", ""
                    ),
                    "attributes": group.get(
                        "attributes", ""
                    ),
                    **state,
                }

    allow_candidates = []
    deny_candidates = []
    inactive_group_matches = []

    for entry in acl_report.get("entries", []):
        principal = _normalize(
            entry.get("principal")
        )

        matched_as = None
        group_state = None

        if principal in user_identifiers:
            matched_as = "CURRENT_USER"

        elif principal in groups:
            matched_as = "TOKEN_GROUP"
            group_state = groups[principal]

        else:
            continue

        denied = bool(entry.get("denied", False))

        candidate = {
            "principal": entry.get("principal"),
            "matched_as": matched_as,
            "rights": entry.get("rights", []),
            "inherited": entry.get(
                "inherited", False
            ),
            "denied": denied,
        }

        if group_state is not None:
            candidate["group_attributes"] = (
                group_state["attributes"]
            )

            allowed_for_match = (
                group_state["enabled_for_deny"]
                if denied
                else group_state["enabled_for_allow"]
            )

            if not allowed_for_match:
                inactive_group_matches.append(
                    candidate
                )
                continue

        if denied:
            deny_candidates.append(candidate)
        else:
            allow_candidates.append(candidate)

    return {
        "analysis_status": "COMPLETED",
        "scope": "CURRENT_PROCESS_TOKEN_ONLY",
        "current_user": current_user,
        "allow_candidates": allow_candidates,
        "deny_candidates": deny_candidates,
        "inactive_group_matches": (
            inactive_group_matches
        ),
        "allow_candidate_count": len(
            allow_candidates
        ),
        "deny_candidate_count": len(
            deny_candidates
        ),
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "This matches visible ACL principals against "
            "the current process token. It does not fully "
            "evaluate Windows access-check semantics, "
            "restricted tokens, implicit principals, "
            "ACE ordering, or all access rights. "
            "It does not establish access for IIS_IUSRS "
            "or any other arbitrary account."
        ),
    }
