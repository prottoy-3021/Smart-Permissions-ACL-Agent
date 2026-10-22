
import re
from typing import Any


# Permission markers that may grant modification,
# deletion, or permission-changing capabilities.
WRITE_RIGHTS = {
    "F", "M", "W", "WD", "AD", "DC",
    "WO", "WDAC", "WA", "WEA", "D",
}

INHERITANCE_FLAGS = {"I", "OI", "CI", "IO", "NP"}

# Match the account followed by its ACL flags.
ACE_PATTERN = re.compile(
    r"^(?P<principal>.+?):"
    r"(?P<flags>(?:\([^)]+\))+)$"
)


def parse_icacls_output(
    output: str,
    target_path: str | None = None,
) -> list[dict[str, Any]]:
    """
    Parse visible Windows ACL entries.

    When target_path is provided, remove the path
    printed before the first ACL principal.

    This is structural ACL parsing, not effective
    access calculation.
    """
    entries = []

    for line in output.splitlines():
        entry = line.strip()

        if not entry:
            continue

        if entry.startswith((
            "Successfully processed",
            "Failed processing",
        )):
            continue

        # icacls prints the target path before the
        # first ACL entry. Remove that prefix.
        if target_path:
            if entry.casefold().startswith(
                target_path.casefold()
            ):
                remainder = entry[len(target_path):]

                if remainder and remainder[0].isspace():
                    entry = remainder.strip()

        match = ACE_PATTERN.match(entry)

        if not match:
            continue

        principal = match.group("principal").strip()

        raw_flags = re.findall(
            r"\(([^)]+)\)",
            match.group("flags"),
        )

        # Some ACL flags contain comma-separated rights.
        flags = [
            item.strip().upper()
            for group in raw_flags
            for item in group.split(",")
            if item.strip()
        ]

        inherited = "I" in flags
        denied = "DENY" in flags

        rights = [
            flag
            for flag in flags
            if flag not in INHERITANCE_FLAGS
            and flag != "DENY"
        ]

        has_write_rights = any(
            right in WRITE_RIGHTS
            for right in rights
        )

        # A deny entry does not grant write access.
        potential_write = (
            has_write_rights and not denied
        )

        entries.append({
            "principal": principal,
            "rights": rights,
            "inherited": inherited,
            "denied": denied,
            "has_write_rights": has_write_rights,
            "potential_write": potential_write,
        })

    return entries


def analyze_windows_acl(
    output: str,
    target_path: str | None = None,
) -> dict[str, Any]:
    """
    Analyze visible ACL entries conservatively.

    This function does not calculate effective access,
    resolve group membership, or modify permissions.
    """
    entries = parse_icacls_output(
        output,
        target_path=target_path,
    )

    write_conflicts = [
        entry
        for entry in entries
        if entry["potential_write"]
    ]

    deny_entries = [
        entry
        for entry in entries
        if entry["denied"]
    ]

    inherited_entries = [
        entry
        for entry in entries
        if entry["inherited"]
    ]

    if write_conflicts or deny_entries:
        assessment = "REVIEW_REQUIRED"
    else:
        assessment = "INSUFFICIENT_EVIDENCE"

    return {
        "entries": entries,
        "potential_write_conflicts": write_conflicts,
        "conflict_count": len(write_conflicts),
        "deny_entries": deny_entries,
        "deny_count": len(deny_entries),
        "inherited_entries": inherited_entries,
        "inherited_count": len(inherited_entries),
        "requires_group_membership_analysis": True,
        "requires_effective_access_verification": True,
        "policy_verified": False,
        "assessment": assessment,
        "note": (
            "Visible ACL entries only. Effective permissions "
            "cannot be established without evaluating access "
            "tokens, group memberships, inheritance, ACE "
            "ordering, and Windows access-check semantics."
        ),
    }
