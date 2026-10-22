import subprocess
from pathlib import Path


def inspect_windows_acl(path):
    """
    Inspect existing Windows ACL entries without changing permissions.

    Raises:
        ValueError: If the target path does not exist.
        RuntimeError: If ACL inspection cannot be completed.
    """

    # Step 1: Validate the target path.
    target = Path(path).resolve()

    if not target.exists():
        raise ValueError(f"Path does not exist: {target}")

    # Step 2: Prepare a read-only ACL inspection command.
    command = ["icacls", str(target)]

    print(f"\nInspecting existing permissions for: {target}")
    print("-" * 55)

    # Step 3: Run icacls and handle execution errors.
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "The icacls command was not found. "
            "This feature requires Windows with icacls available."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "ACL inspection timed out. No permission changes were made."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Could not execute ACL inspection: {exc}"
        ) from exc

    # Step 4: Reject unsuccessful inspections.
    if result.returncode != 0:
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Windows returned an unspecified ACL inspection error."
        )

        raise RuntimeError(
            f"ACL inspection failed for {target}: {error_message}"
        )

    # Step 5: Reject empty output instead of treating it as valid ACL data.
    if not result.stdout.strip():
        raise RuntimeError(
            "ACL inspection returned no output. "
            "The permissions cannot be safely evaluated."
        )

    # Step 6: Display and return the inspected ACL.
    print(result.stdout)

    if result.stderr.strip():
        print("Additional information:")
        print(result.stderr)

    return result.stdout
