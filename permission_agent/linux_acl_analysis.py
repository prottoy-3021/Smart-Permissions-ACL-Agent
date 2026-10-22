
"""
Linux POSIX ACL parsing and preliminary risk analysis.

Uses getfacl output.
No permission-changing commands are executed.
"""

import re


ACL_PATTERN = re.compile(
    r"^(default:)?"
    r"(user|group|mask|other):"
    r"([^:]*):([r-][w-][x-])$"
)

BASE_TYPES = {
    ("user", ""),
    ("group", ""),
    ("other", ""),
}


def _intersect_permissions(permissions, mask):
    """Apply a POSIX ACL mask to rwx permissions."""
    return "".join(
        symbol if symbol == mask[index] else "-"
        for index, symbol in enumerate(permissions)
    )


def parse_linux_acl(output):
    """
    Parse standard getfacl output.

    Reports access and default ACLs separately.
    Does not identify the current Linux user's
    complete effective access.
    """
    entries = []
    metadata = {}
    errors = []

    for line_number, raw_line in enumerate(
        output.splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            for key in ("file", "owner", "group", "flags"):
                prefix = f"# {key}:"

                if line.startswith(prefix):
                    metadata[key] = (
                        line[len(prefix):].strip()
                    )
            continue

        # Remove getfacl's optional #effective comment.
        acl_text = line.split("#", 1)[0].strip()

        match = ACL_PATTERN.fullmatch(acl_text)

        if not match:
            errors.append({
                "line": line_number,
                "content": line,
                "reason": "Unsupported or malformed ACL entry",
            })
            continue

        default_prefix, kind, name, permissions = (
            match.groups()
        )

        entries.append({
            "scope": (
                "default" if default_prefix
                else "access"
            ),
            "type": kind,
            "name": name,
            "permissions": permissions,
            "effective_permissions": permissions,
            "mask_applied": False,
        })

    for scope in ("access", "default"):
        scope_entries = [
            entry for entry in entries
            if entry["scope"] == scope
        ]

        masks = [
            entry["permissions"]
            for entry in scope_entries
            if entry["type"] == "mask"
        ]

        mask = masks[0] if len(masks) == 1 else None

        if len(masks) > 1:
            errors.append({
                "scope": scope,
                "reason": "Multiple ACL mask entries",
            })

        for entry in scope_entries:
            # The mask affects named users and all
            # group entries, including the owning group.
            mask_applies = (
                entry["type"] == "group"
                or (
                    entry["type"] == "user"
                    and bool(entry["name"])
                )
            )

            if mask_applies and mask is not None:
                entry["effective_permissions"] = (
                    _intersect_permissions(
                        entry["permissions"],
                        mask,
                    )
                )
                entry["mask_applied"] = True

            entry["potential_write"] = (
                entry["type"] not in ("mask", "other")
                and "w" in entry["effective_permissions"]
            ) or (
                entry["type"] == "other"
                and "w" in entry["effective_permissions"]
            )

            if entry["type"] == "mask":
                entry["potential_write"] = False

        if scope_entries:
            present = {
                (item["type"], item["name"])
                for item in scope_entries
            }

            missing = BASE_TYPES - present

            if missing:
                errors.append({
                    "scope": scope,
                    "reason": (
                        "Missing required base ACL entries"
                    ),
                    "missing": sorted(
                        f"{kind}:{name}"
                        for kind, name in missing
                    ),
                })

            has_named_entries = any(
                (
                    item["type"] == "user"
                    and bool(item["name"])
                ) or (
                    item["type"] == "group"
                    and bool(item["name"])
                )
                for item in scope_entries
            )

            if has_named_entries and not masks:
                errors.append({
                    "scope": scope,
                    "reason": (
                        "Named ACL entries require a mask"
                    ),
                })

    return {
        "metadata": metadata,
        "entries": entries,
        "parse_errors": errors,
    }


def analyze_linux_acl(output):
    """
    Analyze visible Linux ACL entries.

    This is a preliminary policy-risk assessment,
    not proof of effective access.
    """
    parsed = parse_linux_acl(output)

    entries = parsed["entries"]

    access_entries = [
        entry for entry in entries
        if entry["scope"] == "access"
    ]

    default_entries = [
        entry for entry in entries
        if entry["scope"] == "default"
    ]

    access_write_entries = [
        entry for entry in access_entries
        if entry["potential_write"]
    ]

    default_write_entries = [
        entry for entry in default_entries
        if entry["potential_write"]
    ]

    errors = list(parsed["parse_errors"])

    if not access_entries:
        errors.append({
            "reason": "No access ACL entries found",
        })

    status = (
        "INCOMPLETE"
        if errors else "COMPLETED"
    )

    findings = []

    if access_write_entries:
        findings.append(
            "Potential write-capable access ACL entries found."
        )

    if default_write_entries:
        findings.append(
            "Default ACL entries may permit writing "
            "on newly created child objects."
        )

    if errors:
        findings.append(
            "ACL data is incomplete or malformed."
        )

    if not findings:
        findings.append(
            "No obvious write-capable entries found; "
            "full policy verification is still required."
        )

    return {
        "analysis_status": status,
        "metadata": parsed["metadata"],
        "entries": entries,
        "access_entry_count": len(access_entries),
        "default_entry_count": len(default_entries),
        "access_write_entries": access_write_entries,
        "default_write_entries": default_write_entries,
        "access_write_count": len(access_write_entries),
        "default_write_count": len(default_write_entries),
        "parse_errors": errors,
        "findings": findings,
        "assessment": (
            "INCOMPLETE_EVIDENCE"
            if errors
            else "REVIEW_REQUIRED"
            if (
                access_write_entries
                or default_write_entries
            )
            else "POLICY_NOT_VERIFIED"
        ),
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "Entry permissions account for the visible "
            "ACL mask. Complete user/group access, "
            "parent-directory traversal, supplementary "
            "groups, filesystem restrictions, and "
            "child-object behavior remain unverified. "
            "No permissions were changed."
        ),
    }
