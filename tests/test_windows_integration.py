
import io
import platform
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from permission_agent.planner import plan_permission_change


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Windows integration tests require Windows",
)


def read_real_acl(path):
    """Read actual Windows permissions without modifying them."""
    result = subprocess.run(
        ["icacls", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def make_request(path):
    return {
        "path": str(path),
        "principal": "IIS_IUSRS",
        "web_server_principal": "IIS_IUSRS",
        "policy": "web_server_and_read_only_others",
        "read": True,
        "write": False,
        "execute": True,
    }


def test_real_windows_acl_inspection(monkeypatch):
    """Test planning against a real temporary Windows folder."""

    monkeypatch.delenv(
        "SMART_PERMISSIONS_INSPECT_IDENTITY",
        raising=False,
    )

    with tempfile.TemporaryDirectory(
        prefix="SmartPermissionsTest_"
    ) as folder:

        before_acl = read_real_acl(folder)

        with redirect_stdout(io.StringIO()):
            report = plan_permission_change(
                make_request(folder),
                system="Windows",
            )

        after_acl = read_real_acl(folder)

        assert report["analysis_status"] == "INSPECTED"
        assert report["decision"] == "PLAN_ONLY"
        assert report["permissions_changed"] is False
        assert report["policy_verified"] is False

        structured = report["acl_analysis"][
            "structured_acl_analysis"
        ]

        assert len(structured["entries"]) > 0
        assert structured["policy_verified"] is False

        # Critical safety verification:
        # ACL must remain identical after planning.
        assert before_acl == after_acl


def test_nonexistent_windows_path_is_blocked():
    """An invalid target must not produce an approved plan."""

    with tempfile.TemporaryDirectory(
        prefix="SmartPermissionsTest_"
    ) as folder:

        missing_path = Path(folder) / "MissingFolder"

        assert not missing_path.exists()

        with redirect_stdout(io.StringIO()):
            report = plan_permission_change(
                make_request(missing_path),
                system="Windows",
            )

        assert report["decision"] == "BLOCKED"
        assert report["permissions_changed"] is False
        assert report["analysis_status"] == "INSPECTION_FAILED"
