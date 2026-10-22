
import subprocess
from pathlib import Path


def apply_windows_acl(request):
    path = Path(request["path"])
    principal = request["principal"]

    if request["read"] and request["write"]:
        rights = "M"
    elif request["read"] and request["execute"]:
        rights = "RX"
    elif request["read"]:
        rights = "R"
    elif request["write"]:
        rights = "W"
    elif request["execute"]:
        rights = "X"
    else:
        raise ValueError("Unsupported permission combination.")

    # Allow the account to use permissions on the folder
    # and inherit them on files and subfolders.
    if path.is_dir():
        rights = f"(OI)(CI){rights}"

    command = [
        "icacls",
        str(path),
        "/grant",
        f"{principal}:{rights}",
    ]

    print("Planned Windows command:")
    print(subprocess.list2cmdline(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr or result.stdout or "icacls failed"
        )

    print(result.stdout)
