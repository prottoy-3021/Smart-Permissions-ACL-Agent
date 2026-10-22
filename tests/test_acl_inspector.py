import subprocess
from unittest.mock import patch

import pytest

from permission_agent.acl_inspector import inspect_windows_acl


def test_missing_path_is_rejected():
    with pytest.raises(ValueError, match="Path does not exist"):
        inspect_windows_acl(
            r"C:\DefinitelyDoesNotExist\MissingFolder"
        )


def test_icacls_failure_is_rejected(tmp_path):
    fake_result = subprocess.CompletedProcess(
        args=["icacls", str(tmp_path)],
        returncode=1,
        stdout="",
        stderr="Access is denied.",
    )

    with patch(
        "permission_agent.acl_inspector.subprocess.run",
        return_value=fake_result,
    ):
        with pytest.raises(RuntimeError, match="Access is denied"):
            inspect_windows_acl(str(tmp_path))


def test_empty_output_is_rejected(tmp_path):
    fake_result = subprocess.CompletedProcess(
        args=["icacls", str(tmp_path)],
        returncode=0,
        stdout="",
        stderr="",
    )

    with patch(
        "permission_agent.acl_inspector.subprocess.run",
        return_value=fake_result,
    ):
        with pytest.raises(RuntimeError, match="returned no output"):
            inspect_windows_acl(str(tmp_path))


def test_timeout_is_rejected(tmp_path):
    with patch(
        "permission_agent.acl_inspector.subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            cmd=["icacls", str(tmp_path)],
            timeout=15,
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            inspect_windows_acl(str(tmp_path))
