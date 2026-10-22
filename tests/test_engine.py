from unittest.mock import patch

from permission_agent.engine import execute_request


def sample_request():
    return {
        "path": r"C:\ACL-Test",
        "principal": r"PROTTOY\prott",
        "read": True,
        "write": False,
        "execute": False,
    }


def test_validation_failure_is_blocked(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=ValueError("Invalid request"),
    ):
        result = execute_request(sample_request())

    output = capsys.readouterr().out

    assert result is False
    assert "REQUEST REJECTED" in output
    assert "No permissions were changed" in output


def test_acl_inspection_failure_is_blocked(capsys):
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
                side_effect=RuntimeError("Inspection failed"),
            ):
                result = execute_request(sample_request())

    output = capsys.readouterr().out

    assert result is False
    assert "ACL INSPECTION FAILED" in output
    assert "No permissions were changed" in output


def test_linux_request_is_blocked(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Linux",
        ):
            result = execute_request(sample_request())

    output = capsys.readouterr().out

    assert result is False
    assert "Linux permission analysis is not yet verified" in output
    assert "No permissions were changed" in output


def test_apply_true_never_authorizes_changes(capsys):
    with patch(
        "permission_agent.engine.validate_request",
        side_effect=lambda request: request,
    ):
        with patch(
            "permission_agent.engine.platform.system",
            return_value="Windows",
        ):
            with patch(
                "permission_agent.engine.plan_permission_change"
            ) as mock_planner:
                result = execute_request(sample_request(), apply=True)

    output = capsys.readouterr().out

    assert result is False
    assert "Permission-changing mode is disabled" in output
    assert "No permissions were changed" in output
    mock_planner.assert_not_called()
