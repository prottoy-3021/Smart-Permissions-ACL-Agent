
import shutil
import subprocess
from pathlib import Path


def apply_linux_acl(request):
    if shutil.which("setfacl") is None:
        raise RuntimeError(
            "setfacl is missing. Install the Linux ACL utilities."
        )

    path = Path(request["path"])
    principal = request["principal"]

    # This MVP treats the principal as a user.
    # Directory read access also needs traversal permission.
    read = request["read"]
    write = request["write"]
    execute = request["execute"] or (
        path.is_dir() and read
    )

    rights = (
        ("r" if read else "-")
        + ("w" if write else "-")
        + ("x" if execute else "-")
    )

    # Use subprocess arguments, not a shell command string.
    command = [
        "setfacl",
        "-m",
        f"u:{principal}:{rights}",
        str(path),
    ]

    print("Planned Linux command:")
    print(" ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr or result.stdout or "setfacl failed"
        )

    print("Linux ACL updated successfully.")
