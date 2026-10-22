
"""
Windows SID-based ACL analysis.

Read-only inspection of the current process identity.
Does not modify permissions or calculate full effective access.
"""

import platform


def _current_user_sid():
    """Retrieve the current process user's SID."""
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_QUERY,
    )

    try:
        user_info = win32security.GetTokenInformation(
            token,
            win32security.TokenUser,
        )
        return win32security.ConvertSidToStringSid(
            user_info[0]
        )
    finally:
        token.Close()


def _lookup_sid(principal):
    """Resolve a Windows principal to its SID."""
    import win32security

    sid, domain, account_type = (
        win32security.LookupAccountName(None, principal)
    )

    return (
        win32security.ConvertSidToStringSid(sid)
    )


def _enabled_membership(sid_string):
    """
    Check enabled membership for the current process.

    A false result does not prove a deny ACE cannot apply.
    """
    import win32security

    sid = win32security.ConvertStringSidToSid(
        sid_string
    )

    return bool(
        win32security.CheckTokenMembership(
            None,
            sid,
        )
    )


def analyze_acl_sid_membership(acl_report):
    """
    Match ACL principals using Windows SIDs.

    Checks the current process identity only.
    Does not verify the requested IIS account's access.
    """

    if platform.system() != "Windows":
        raise RuntimeError(
            "SID analysis is available only on Windows."
        )

    current_sid = _current_user_sid()

    analyzed_entries = []

    for entry in acl_report.get("entries", []):
        principal = entry.get("principal", "")

        result = {
            "principal": principal,
            "rights": entry.get("rights", []),
            "denied": entry.get("denied", False),
            "inherited": entry.get("inherited", False),
            "resolved_sid": None,
            "match": "UNRESOLVED",
            "enabled_for_allow": False,
        }

        if not principal:
            analyzed_entries.append(result)
            continue

        try:
            principal_sid = _lookup_sid(principal)
            result["resolved_sid"] = principal_sid

            if principal_sid.casefold() == current_sid.casefold():
                result["match"] = "CURRENT_USER"
                result["enabled_for_allow"] = True

            elif _enabled_membership(principal_sid):
                result["match"] = "ENABLED_GROUP"
                result["enabled_for_allow"] = True

            else:
                result["match"] = "NOT_CONFIRMED"

        except (OSError, RuntimeError, ValueError) as exc:
            result["match"] = "UNRESOLVED"
            result["error"] = str(exc)

        analyzed_entries.append(result)

    user_matches = sum(
        item["match"] == "CURRENT_USER"
        for item in analyzed_entries
    )

    group_matches = sum(
        item["match"] == "ENABLED_GROUP"
        for item in analyzed_entries
    )

    unresolved = sum(
        item["match"] == "UNRESOLVED"
        for item in analyzed_entries
    )

    return {
        "analysis_status": "COMPLETED",
        "scope": "CURRENT_PROCESS_ONLY",
        "current_user_sid": current_sid,
        "entries": analyzed_entries,
        "current_user_match_count": user_matches,
        "enabled_group_match_count": group_matches,
        "unresolved_count": unresolved,
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "This report identifies direct user and enabled "
            "group SID matches. Disabled and deny-only groups "
            "require additional analysis for deny rules. "
            "Full Windows AccessCheck semantics are not "
            "implemented. No permissions were changed."
        ),
    }
