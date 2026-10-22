
from unittest.mock import patch

import pytest

from permission_agent.engine import execute_request


def make_request():
    return {
        "path": r"C:\ACL-Test",
        "principal": r"PROTTOY\prott",
        "read": True,
        "write": False,
        "execute": False,
    }


def make_web_server_request():
    return {
        "path": r"C:\ACL-Test",
        "principal": "IIS_IUSRS",
        "read": True,
        "write": False,
        "execute": True,
        "policy": "web_server_and_read_only_others",
        "web_server_principal": "IIS_IUSRS",
        "others_read_only": True,
    }


def test_evaluation_blocks_unverified_windows_request(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Windows",
        ):
            with patch(
                "permission_agent.engine.plan_permission_change",
                return_value=False,
            ):
                result = execute_request(make_request())

    output = capsys.readouterr().out

    assert result is False
    assert "Request BLOCKED" in output
    assert "No permissions were changed" in output


def test_evaluation_blocks_linux_request(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Linux",
        ):
            result = execute_request(make_request())

    output = capsys.readouterr().out

    assert result is False
    assert "Linux permission analysis is not yet verified" in output


def test_evaluation_blocks_apply_mode(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Windows",
        ):
            result = execute_request(make_request(), apply=True)

    output = capsys.readouterr().out

    assert result is False
    assert "Permission-changing mode is disabled" in output


def test_evaluation_rejects_invalid_request(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=ValueError("Invalid path"),
    ):
        result = execute_request(make_request())

    output = capsys.readouterr().out

    assert result is False
    assert "REQUEST REJECTED" in output


def test_web_server_request_contains_read_execute_policy():
    request = make_web_server_request()

    assert request["policy"] == "web_server_and_read_only_others"
    assert request["web_server_principal"] == "IIS_IUSRS"
    assert request["read"] is True
    assert request["write"] is False
    assert request["execute"] is True
    assert request["others_read_only"] is True


def test_web_server_request_does_not_claim_verification():
    request = make_web_server_request()

    assert request["policy_verified"] is False if "policy_verified" in request else True


def test_invalid_request_is_rejected_before_planning(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=ValueError("Invalid path"),
    ):
        with patch(
            "permission_agent.engine.plan_permission_change",
        ) as planner:
            result = execute_request(make_request())

    assert result is False
    planner.assert_not_called()


def test_apply_mode_never_calls_planner(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Windows",
        ):
            with patch(
                "permission_agent.engine.plan_permission_change",
            ) as planner:
                result = execute_request(make_request(), apply=True)

    assert result is False
    planner.assert_not_called()
