import re


def parse_acl_entries(acl_output):
    """
    Classify common entries from Windows icacls output.

    This is a text parser, not a complete Windows effective-access
    calculator. Unrecognized formats must be reviewed separately.
    """

    entries = []

    for raw_line in acl_output.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("Successfully processed"):
            continue

        # Skip common icacls summary/error lines.
        if line.startswith("processed ") or line.startswith("Failed processing"):
            continue

        # Typical entry: DOMAIN\\User:(I)(OI)(CI)(F)
        match = re.match(r"^(.*?):(.*)$", line)

        if not match:
            continue

        principal = match.group(1).strip()
        permission_text = match.group(2).strip()
        permission_upper = permission_text.upper()

        entries.append(
            {
                "principal": principal,
                "permissions": permission_text,
                "inherited": "(I)" in permission_upper,
                "full_control": "(F)" in permission_upper,
                "explicit_deny": "(DENY)" in permission_upper,
                "broad_principal": principal.casefold()
                in {
                    "everyone",
                    "authenticated users",
                    "builtin\\users",
                    "users",
                    "nt authority\\authenticated users",
                },
            }
        )

    return entries
