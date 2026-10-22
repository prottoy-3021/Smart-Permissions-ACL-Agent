
import csv
import io
import json
import platform
import subprocess


def _run_whoami(arguments):
    """
    Run a read-only Windows identity command.
    No permissions are modified.
    """
    result = subprocess.run(
        ["whoami", *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or "Windows identity inspection failed."
        )

    return result.stdout


def parse_user_output(output):
    """
    Parse the CSV output of:
    whoami /user /fo csv /nh
    """
    rows = list(csv.reader(io.StringIO(output)))

    for row in rows:
        if len(row) >= 2:
            username = row[0].strip()
            sid = row[1].strip()

            if username and sid:
                return {
                    "username": username,
                    "sid": sid,
                }

    raise ValueError(
        "Could not identify the current Windows user."
    )


def parse_groups_output(output):
    """
    Parse the CSV output of:
    whoami /groups /fo csv /nh

    The output describes groups in the current
    process access token. It does not resolve
    arbitrary users' group memberships.
    """
    groups = []

    rows = csv.reader(io.StringIO(output))

    for row in rows:
        if len(row) < 4:
            continue

        group_name = row[0].strip()
        group_type = row[1].strip()
        sid = row[2].strip()
        attributes = row[3].strip()

        if not group_name or not sid:
            continue

        groups.append({
            "group_name": group_name,
            "group_type": group_type,
            "sid": sid,
            "attributes": attributes,
        })

    return groups


def inspect_current_windows_identity():
    """
    Inspect the current Windows security identity.

    This function does not change any ACLs and
    does not calculate effective permissions.
    """
    if platform.system() != "Windows":
        raise RuntimeError(
            "Windows identity inspection requires Windows."
        )

    user_output = _run_whoami([
        "/user", "/fo", "csv", "/nh"
    ])

    groups_output = _run_whoami([
        "/groups", "/fo", "csv", "/nh"
    ])

    user = parse_user_output(user_output)
    groups = parse_groups_output(groups_output)

    return {
        "inspection_status": "COMPLETED",
        "scope": "CURRENT_PROCESS_TOKEN",
        "current_user": user,
        "groups": groups,
        "group_count": len(groups),
        "effective_access_verified": False,
        "permissions_changed": False,
        "note": (
            "Group information belongs to the current "
            "Windows process token only. Group attributes "
            "must be considered when evaluating access. "
            "This does not establish permissions for "
            "other users or prove effective ACL access."
        ),
    }


if __name__ == "__main__":
    try:
        report = inspect_current_windows_identity()
        print(json.dumps(report, indent=4))

    except (OSError, RuntimeError, ValueError) as exc:
        print("IDENTITY INSPECTION FAILED:", exc)
        raise SystemExit(1)
