
"""
Windows read-only policy gap analysis.

Analyzes native Windows ACL entries without modifying them.

This module does not prove effective access for all users.
"""

# Rights associated with writing, deletion, or ACL modification.
WRITE_MASK = (
    0x00000002  # Write data / create file
    | 0x00000004  # Append data / create subdirectory
    | 0x00000010  # Write extended attributes
    | 0x00000040  # Delete child
    | 0x00000100  # Write attributes
    | 0x00010000  # Delete
    | 0x00040000  # Change permissions
    | 0x00080000  # Take ownership
    | 0x40000000  # Generic write
    | 0x10000000  # Generic all
)

READ_MASK = (
    0x00000001  # Read data / list directory
    | 0x80000000  # Generic read
    | 0x10000000  # Generic all
)

EXECUTE_MASK = (
    0x00000020  # Execute / traverse
    | 0x20000000  # Generic execute
    | 0x10000000  # Generic all
)

PRIVILEGED_SIDS = {
    "S-1-5-18",      # SYSTEM
    "S-1-5-32-544",  # Built-in Administrators
}


def resolve_windows_sid(principal):
    """Resolve an account or group to a Windows SID."""
    import win32security

    sid, _, _ = win32security.LookupAccountName(
        None,
        principal,
    )

    return win32security.ConvertSidToStringSid(sid)


def _parse_mask(value):
    """Read an integer or hexadecimal access mask."""
    if isinstance(value, int):
        return value

    if isinstance(value, str):
        return int(value.strip(), 0)

    raise ValueError("Invalid ACL access mask.")


def audit_read_only_policy(
    native_report,
    target_principal="IIS_IUSRS",
    target_sid=None,
):
    """
    Identify gaps in the proposed policy:

    - Target principal should have read/execute access.
    - Other principals should not have write access,
      subject to explicitly defined exceptions.

    Results are advisory and remain unverified.
    """
    findings = []
    actions = []
    target_rx_candidates = []
    write_grants = []
    inherited_entries = []
    deny_entries = []

    target_sid_normalized = (
        str(target_sid).casefold()
        if target_sid
        else None
    )

    def add_finding(code, severity, description):
        findings.append({
            "code": code,
            "severity": severity,
            "description": description,
        })

    null_dacl = native_report.get("null_dacl")

    entries = native_report.get("entries", [])

    if native_report.get("inspection_status") != "COMPLETED":
        add_finding(
            "INSPECTION_INCOMPLETE",
            "HIGH",
            "Native Windows ACL inspection did not complete.",
        )

    if null_dacl is True:
        add_finding(
            "NULL_DACL",
            "CRITICAL",
            "The target has a NULL DACL. "
            "The intended read-only restriction is not established.",
        )

    elif null_dacl is False and not entries:
        add_finding(
            "EMPTY_DACL",
            "HIGH",
            "The DACL contains no ACEs. "
            "Required read and execute access is not established.",
        )

    if not target_sid_normalized:
        add_finding(
            "TARGET_SID_UNRESOLVED",
            "HIGH",
            "The web-server principal SID is unavailable. "
            "Direct ACE matching cannot be completed.",
        )

    for entry in entries:
        ace_type = str(
            entry.get("type", "OTHER")
        ).upper()

        sid = str(
            entry.get("sid") or ""
        )

        inherited = bool(
            entry.get("inherited", False)
        )

        inherit_only = bool(
            entry.get("inherit_only", False)
        )

        if inherited:
            inherited_entries.append(entry)

        if ace_type == "DENY":
            deny_entries.append(entry)

            if (
                target_sid_normalized
                and sid.casefold() == target_sid_normalized
                and not inherit_only
            ):
                add_finding(
                    "TARGET_DENY_REVIEW",
                    "HIGH",
                    "A deny ACE applies directly to the target "
                    "principal. Its rights require review.",
                )

            continue

        if ace_type != "ALLOW":
            add_finding(
                "UNSUPPORTED_ACE",
                "HIGH",
                "An ACE type requires additional decoding "
                "before the policy can be evaluated.",
            )
            continue

        try:
            mask = _parse_mask(
                entry.get("mask")
            )
        except (TypeError, ValueError):
            add_finding(
                "INVALID_ACCESS_MASK",
                "HIGH",
                "An ACE has an unreadable access mask.",
            )
            continue

        # Inherit-only ACEs do not grant access
        # directly to the inspected folder.
        if inherit_only:
            continue

        is_target = bool(
            target_sid_normalized
            and sid.casefold() == target_sid_normalized
        )

        has_read = bool(mask & READ_MASK)
        has_execute = bool(mask & EXECUTE_MASK)
        has_write = bool(mask & WRITE_MASK)

        if is_target and has_read and has_execute:
            target_rx_candidates.append(entry)

        if has_write:
            write_grants.append(entry)

            if is_target:
                add_finding(
                    "TARGET_EXCESSIVE_RIGHTS",
                    "HIGH",
                    "The target principal has an ACE with "
                    "potential write or modification rights.",
                )

            elif sid.upper() in PRIVILEGED_SIDS:
                add_finding(
                    "PRIVILEGED_EXCEPTION_REVIEW",
                    "HIGH",
                    "A privileged Windows identity has "
                    "potential write rights. An explicit "
                    "policy exception requires review.",
                )

            elif not target_sid_normalized:
                add_finding(
                    "UNCLASSIFIED_WRITE_GRANT",
                    "HIGH",
                    "A write-capable ACE was found, but the "
                    "target SID is not resolved.",
                )

            else:
                add_finding(
                    "OTHER_WRITE_GRANT_REVIEW",
                    "HIGH",
                    "Another principal has a potentially "
                    "write-capable allow ACE.",
                )

    if (
        target_sid_normalized
        and not target_rx_candidates
        and null_dacl is not True
    ):
        add_finding(
            "NO_DIRECT_TARGET_RX_CANDIDATE",
            "HIGH",
            "No direct read-and-execute allow candidate "
            "was identified for the target SID. "
            "Group-based access may still exist.",
        )

    actions.extend([
        "Confirm the actual Windows token used by the web-server process.",
        "Review all write-capable allow ACEs and their group memberships.",
        "Define whether SYSTEM and Administrators are policy exceptions.",
        "Review inherited ACEs and permissions on child files and folders.",
        "Verify read and execute access using the intended security identity.",
        "Test the final policy in an isolated folder before any deployment.",
    ])

    if deny_entries:
        actions.append(
            "Review deny ACE ordering and affected rights."
        )

    return {
        "audit_status": "COMPLETED",
        "assessment": (
            "REVIEW_REQUIRED"
            if findings
            else "UNVERIFIED"
        ),
        "target_principal": target_principal,
        "target_sid": target_sid,
        "target_rx_candidate_count": len(
            target_rx_candidates
        ),
        "potential_write_grant_count": len(
            write_grants
        ),
        "inherited_entry_count": len(
            inherited_entries
        ),
        "deny_entry_count": len(
            deny_entries
        ),
        "findings": findings,
        "recommended_review_actions": actions,
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "This is a policy-gap audit, not a complete "
            "Windows authorization check. ACE masks alone "
            "do not establish effective access for users "
            "and groups. No ACL changes are performed."
        ),
    }
