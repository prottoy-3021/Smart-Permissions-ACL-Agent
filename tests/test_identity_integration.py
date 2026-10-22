
from unittest.mock import patch

from permission_agent.planner import plan_permission_change


def make_request():
    return {
        "path": r"C:\ACL-Test",
        "principal": "IIS_IUSRS",
        "web_server_principal": "IIS_IUSRS",
        "policy": "web_server_and_read_only_others",
        "read": True,
        "write": False,
        "execute": True,
    }


SAMPLE_ACL = r"C:\ACL-Test BUILTIN\Users:(RX)"


def test_identity_inspection_disabled_by_default(
    monkeypatch,
):
    monkeypatch.delenv(
        "SMART_PERMISSIONS_INSPECT_IDENTITY",
        raising=False,
    )

    with patch(
        "permission_agent.planner._windows_inspection",
        return_value=SAMPLE_ACL,
    ):
        with patch(
            "permission_agent.planner.inspect_current_windows_identity"
        ) as identity_mock:
            with patch("builtins.print"):
                report = plan_permission_change(
                    make_request(),
                    system="Windows",
                )

    identity_mock.assert_not_called()
    assert "identity_inspection" not in report
    assert report["permissions_changed"] is False


def test_identity_inspection_added_when_enabled(
    monkeypatch,
):
    monkeypatch.setenv(
        "SMART_PERMISSIONS_INSPECT_IDENTITY",
        "1",
    )

    sample_identity = {
        "inspection_status": "COMPLETED",
        "scope": "CURRENT_PROCESS_TOKEN",
        "current_user": {
            "username": r"PROTTOY\prott",
            "sid": "S-1-5-21-test",
        },
        "groups": [],
        "group_count": 0,
        "effective_access_verified": False,
        "permissions_changed": False,
    }

    with patch(
        "permission_agent.planner._windows_inspection",
        return_value=SAMPLE_ACL,
    ):
        with patch(
            "permission_agent.planner.inspect_current_windows_identity",
            return_value=sample_identity,
        ):
            with patch("builtins.print"):
                report = plan_permission_change(
                    make_request(),
                    system="Windows",
                )

    assert report["identity_inspection"] == sample_identity
    assert report["decision"] == "PLAN_ONLY"
    assert report["permissions_changed"] is False
    assert report["policy_verified"] is False


def test_identity_inspection_failure_does_not_block_plan(
    monkeypatch,
):
    monkeypatch.setenv(
        "SMART_PERMISSIONS_INSPECT_IDENTITY",
        "1",
    )

    with patch(
        "permission_agent.planner._windows_inspection",
        return_value=SAMPLE_ACL,
    ):
        with patch(
            "permission_agent.planner.inspect_current_windows_identity",
            side_effect=RuntimeError("Identity unavailable"),
        ):
            with patch("builtins.print"):
                report = plan_permission_change(
                    make_request(),
                    system="Windows",
                )

    assert (
        report["identity_inspection"]["inspection_status"]
        == "FAILED"
    )
    assert report["decision"] == "PLAN_ONLY"
    assert report["permissions_changed"] is False
