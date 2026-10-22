
import re
from pathlib import PureWindowsPath, PurePosixPath


def is_absolute_path(path):
    """Recognize absolute Windows and Linux paths on any OS."""
    windows_path = PureWindowsPath(path)
    linux_path = PurePosixPath(path)

    return windows_path.is_absolute() or linux_path.is_absolute()


def parse_request(text):
    """
    Parse supported permission requests into a structured plan.

    This parser identifies intent and proposes a command.
    It never changes permissions or executes system commands.
    """
    text = text.strip().rstrip(".").strip()

    # Policy 1:
    # Give the web server read/execute access and keep
    # everyone else read-only.
    match = re.fullmatch(
        r"make\s+"
        r"(?:the\s+www\s+folder\s+at\s+)?"
        r"(.+?)\s+"
        r"accessible\s+to\s+"
        r"(.+?)"
        r"(?:\s*,?\s*but\s+"
        r"(?:strictly\s+)?read[- ]only\s+for\s+everyone\s+else"
        r"|\s+with\s+read\s+and\s+execute\s+permissions"
        r"\s*,?\s*and\s+keep\s+everyone\s+else\s+read[- ]only)",
        text,
        re.IGNORECASE,
    )

    if match:
        path = match.group(1).strip().strip("'\"")
        web_server = match.group(2).strip().rstrip(",")

        if not path or not web_server:
            raise ValueError(
                "A folder path and web-server account are required."
            )

        if not is_absolute_path(path):
            raise ValueError("Use an absolute path.")

        # Build a proposed command; do not execute it here.
        proposed_command = [
            "icacls",
            path,
            "/grant",
            f"{web_server}:(OI)(CI)(RX)",
        ]

        return {
            "path": path,
            "principal": web_server,
            "read": True,
            "write": False,
            "execute": True,
            "policy": "web_server_and_read_only_others",
            "web_server_principal": web_server,
            "others_read_only": True,
            "proposed_command": proposed_command,
            "decision": "PLAN_ONLY",
            "permissions_changed": False,
            "policy_verified": False,
        }

    # Policy 2:
    # Make a folder read-only for a named principal.
    match = re.fullmatch(
        r"make\s+(.+?)\s+read[- ]only\s+for\s+(.+)",
        text,
        re.IGNORECASE,
    )

    if match:
        path = match.group(1).strip().strip("'\"")
        principal = match.group(2).strip()

        if not is_absolute_path(path):
            raise ValueError("Use an absolute path.")

        return {
            "path": path,
            "principal": principal,
            "read": True,
            "write": False,
            "execute": False,
        }

    # Policy 3:
    # Allow a named principal to read and write a folder.
    match = re.fullmatch(
        r"allow\s+(.+?)\s+to\s+read\s+and\s+write\s+(.+)",
        text,
        re.IGNORECASE,
    )

    if match:
        path = match.group(2).strip().strip("'\"")
        principal = match.group(1).strip()

        if not is_absolute_path(path):
            raise ValueError("Use an absolute path.")

        return {
            "path": path,
            "principal": principal,
            "read": True,
            "write": True,
            "execute": False,
        }

    # Unsupported requests are rejected.
    raise ValueError(
        "Request not recognized or unsupported. Try: "
        "'Make the www folder at C:\\site\\www accessible to "
        "IIS_IUSRS, but read-only for everyone else.'"
    )
