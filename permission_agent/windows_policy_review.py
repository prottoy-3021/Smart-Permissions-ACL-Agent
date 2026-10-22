
"""
Windows ACL policy exception review.

Classifies visible write-capable ACL entries as:
- Target principal
- Explicitly approved exception
- Other principal requiring review

No permission-changing commands are executed.
"""

from permission_agent.windows_policy_audit import WRITE_MASK


PRIVILEGED_SIDS = {
    "S-1-5-18": "LOCAL SYSTEM",
    "S-1-5-32-544": "BUILTIN Administrators",
}


def _normalize_sid(sid):
    return str(sid or "").strip().casefold()


def _access_mask(value):
    if isinstance(value, bool):
        raise ValueError("Invalid access mask")

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        return int(value, 0)

    raise ValueError("Invalid access mask")


def review_windows_policy(
    native_report,
    target_sid=None,
    approved_writer_sids=(),
):
    """
    Review native ACL entries against a proposed policy.

    approved_writer_sids:
        Explicitly documented exceptions permitted to
        retain write access.

    Important:
        Exceptions classify findings only.
        They do not grant access or verify a policy.
    """

    approved = {
        _normalize_sid(sid)
        for sid in approved_writer_sids
        if sid
    }

    target = _normalize_sid(target_sid)

    findings = []
    target_write_entries = []
    exception_write_entries = []
    other_write_entries = []
    privileged_entries = []
    deny_entries = []
    inherited_entries = []
    unsupported_entries = []

    status = native_report.get("inspection_status")

    if status != "COMPLETED":
        findings.append(
            "Native Windows ACL inspection is incomplete."
        )

    null_dacl = native_report.get("null_dacl")

    if null_dacl is True:
        findings.append(
            "NULL DACL detected: unrestricted access risk."
        )

    elif null_dacl is None:
        findings.append(
            "DACL status is unavailable."
        )

    if not target:
        findings.append(
            "The target principal SID is unresolved."
        )

    for entry in native_report.get("entries", []):
        ace_type = str(
            entry.get("type", "OTHER")
        ).upper()

        sid = _normalize_sid(entry.get("sid"))

        if entry.get("inherited", False):
            inherited_entries.append(entry)

        if ace_type == "DENY":
            deny_entries.append(entry)
            continue

        if ace_type != "ALLOW":
            unsupported_entries.append(entry)
            continue

        try:
            mask = _access_mask(entry.get("mask"))
        except (ValueError, TypeError):
            unsupported_entries.append(entry)
            continue

        if not (mask & WRITE_MASK):
            continue

        # An inherit-only ACE does not apply directly
        # to the current directory, but may affect children.
        if entry.get("inherit_only", False):
            findings.append(
                "An inherit-only write ACE requires "
                "child-object permission review."
            )
            continue

        if not sid:
            unsupported_entries.append(entry)
            continue

        
        if sid.upper() in PRIVILEGED_SIDS:
            privileged_entries.append(entry)


        if target and sid == target:
            target_write_entries.append(entry)

        elif sid in approved:
            exception_write_entries.append(entry)

        else:
            other_write_entries.append(entry)

    if target_write_entries:
        findings.append(
            "The target principal has a potentially "
            "write-capable allow ACE."
        )

    if other_write_entries:
        findings.append(
            "Other principals have potentially "
            "write-capable allow ACEs."
        )

    if privileged_entries:
        findings.append(
            "Privileged account permissions require "
            "explicit policy decisions."
        )

    if deny_entries:
        findings.append(
            "Deny ACEs require access-order review."
        )

    if inherited_entries:
        findings.append(
            "Inherited permissions and parent folders "
            "require review."
        )

    if unsupported_entries:
        findings.append(
            "Some ACL entries could not be fully analyzed."
        )

    evidence_complete = (
        status == "COMPLETED"
        and null_dacl is False
        and bool(target)
        and not unsupported_entries
    )

    return {
        "review_status": (
            "MANUAL_REVIEW_REQUIRED"
            if evidence_complete
            else "INCOMPLETE_EVIDENCE"
        ),
        "target_sid": target_sid,
        "approved_writer_sids": sorted(approved),
        "target_write_entries": target_write_entries,
        "exception_write_entries": exception_write_entries,
        "other_write_entries": other_write_entries,
        "privileged_entries": privileged_entries,
        "deny_entry_count": len(deny_entries),
        "inherited_entry_count": len(inherited_entries),
        "unsupported_entry_count": len(
            unsupported_entries
        ),
        "findings": findings,
        "ready_to_apply": False,
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "Advisory ACL policy review only. "
            "Explicit exceptions do not establish "
            "effective access. Group memberships, "
            "child objects, ordered ACE processing, "
            "and the actual web-server token must "
            "be evaluated separately."
        ),
    }
