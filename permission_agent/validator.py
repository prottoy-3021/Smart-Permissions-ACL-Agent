
from pathlib import Path, PureWindowsPath, PurePosixPath
import platform
import subprocess


def validate_request(request):
    raw_path = str(request["path"]).strip()

    # Recognize absolute paths for both operating systems.
    windows_path = PureWindowsPath(raw_path)
    linux_path = PurePosixPath(raw_path)

    if platform.system() == "Windows":
        if not windows_path.is_absolute():
            raise ValueError("Use an absolute path.")

        path = Path(raw_path).expanduser()
    else:
        if not linux_path.is_absolute():
            raise ValueError("Use an absolute path.")

        path = Path(raw_path).expanduser()

    if not path.exists():
        raise ValueError("The target path does not exist.")

    if not any(
        request.get(key, False)
        for key in ("read", "write", "execute")
    ):
        raise ValueError("At least one permission must be enabled.")

    principal = request.get("principal", "").strip()

    if not principal:
        raise ValueError("A user or group must be specified.")

    if principal.casefold() in {
        "everyone", "everyone else", "all users", "all",
    }:
        raise ValueError(
            "Broad principal changes require a separate "
            "explicitly reviewed policy."
        )

    # On Windows, check whether the account or group can be resolved.
    if platform.system() == "Windows":
        escaped_principal = principal.replace("'", "''")
        command_text = (
            f"$account = '{escaped_principal}'; "
            "try { "
            "$null = (New-Object System.Security.Principal.NTAccount($account))"
            ".Translate([System.Security.Principal.SecurityIdentifier]); "
            "exit 0 "
            "} catch { exit 1 }"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command_text,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise ValueError(
                f"Windows could not resolve account or group: {principal}"
            )

    validated_request = request.copy()
    validated_request["principal"] = principal
    validated_request["path"] = str(path.resolve())

    return validated_request
