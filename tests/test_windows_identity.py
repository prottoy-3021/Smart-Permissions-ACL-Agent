
from unittest.mock import patch
import subprocess

import pytest

from permission_agent.windows_identity import (
    parse_user_output,
    parse_groups_output,
    inspect_current_windows_identity,
    _run_whoami,
)


USER_OUTPUT = (
    '"PROTTOY\\prott","S-1-5-21-1234-1001"\n'
)

GROUP_OUTPUT = (
    '"BUILTIN\\Administrators","Alias",'
    '"S-1-5-32-544","Enabled group"\n'
    '"BUILTIN\\Users","Alias",'
    '"S-1-5-32-545","Enabled group"\n'
)


def test_parse_windows_username():
    result = parse_user_output(USER_OUTPUT)

    assert result["username"] == "PROTTOY\\prott"


def test_parse_windows_user_sid():
    result = parse_user_output(USER_OUTPUT)

    assert result["sid"] == "S-1-5-21-1234-1001"


def test_parse_group_memberships():
    groups = parse_groups_output(GROUP_OUTPUT)

    assert len(groups) == 2

    assert groups[0]["group_name"] == (
        "BUILTIN\\Administrators"
    )


def test_parse_group_attributes():
    groups = parse_groups_output(GROUP_OUTPUT)

    assert groups[1]["attributes"] == (
        "Enabled group"
    )


def test_reject_invalid_user_output():
    with pytest.raises(ValueError):
        parse_user_output("")


def test_reject_non_windows_platform():
    with patch(
        "permission_agent.windows_identity.platform.system",
        return_value="Linux",
    ):
        with pytest.raises(RuntimeError):
            inspect_current_windows_identity()


def test_identity_inspection_is_read_only():
    user_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=USER_OUTPUT,
        stderr="",
    )

    group_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=GROUP_OUTPUT,
        stderr="",
    )

    with patch(
        "permission_agent.windows_identity.platform.system",
        return_value="Windows",
    ):
        with patch(
            "permission_agent.windows_identity.subprocess.run",
            side_effect=[user_result, group_result],
        ) as mock_run:

            report = inspect_current_windows_identity()

    assert report["group_count"] == 2
    assert report["permissions_changed"] is False
    assert report["effective_access_verified"] is False

    commands = [
        call.args[0] for call in mock_run.call_args_list
    ]

    assert commands == [
        ["whoami", "/user", "/fo", "csv", "/nh"],
        ["whoami", "/groups", "/fo", "csv", "/nh"],
    ]
