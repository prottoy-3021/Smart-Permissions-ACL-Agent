
from unittest.mock import patch

from permission_agent.planner import plan_permission_change


def make_request():
    return {
        "path": r"C:\ACL-Test",
        "principal": "IIS_IUSRS",
        "web_server_principal": "IIS_IUSRS",
        "read": True,
        "write": False,
        "execute": True,
        "policy": "web_server_and_read_only_others",
        "others_read_only": True,
    }


def test_windows_plan_is_reported_without_changes():
    with patch(
        "permission_agent.planner._windows_inspection",
        return_value=r"C:\ACL-Test BUILTIN\Users:(RX)",
    ):
        with patch("builtins.print"):
            report = plan_permission_change(
                make_request(), system="Windows"
            )

    assert report["decision"] == "PLAN_ONLY"
    assert report["permissions_changed"] is False
    assert report["analysis_status"] == "INSPECTED"
    assert report["web_server_principal"] == "IIS_IUSRS"
    assert report["proposed_plan"][0]["executed"] is False


def test_linux_plan_is_reported_without_changes():
    with patch(
        "permission_agent.planner._linux_inspection",
        return_value="user::rwx\ngroup::r-x\nother::r-x",
    ):
        with patch("builtins.print"):
            report = plan_permission_change(
                make_request(), system="Linux"
            )

    assert report["decision"] == "PLAN_ONLY"
    assert report["permissions_changed"] is False
    assert report["proposed_plan"][0]["executed"] is False


def test_inspection_failure_blocks_plan():
    with patch(
        "permission_agent.planner._windows_inspection",
        side_effect=RuntimeError("inspection failed"),
    ):
        with patch("builtins.print"):
            report = plan_permission_change(
                make_request(), system="Windows"
            )

    assert report["decision"] == "BLOCKED"
    assert report["analysis_status"] == "INSPECTION_FAILED"
    assert report["permissions_changed"] is False


def test_wrong_policy_is_blocked():
    request = make_request()
    request["policy"] = "unrelated_policy"

    with patch("builtins.print"):
        report = plan_permission_change(request, system="Windows")

    assert report["decision"] == "BLOCKED"
    assert report["permissions_changed"] is False


def test_planning_does_not_execute_commands():
    with patch(
        "permission_agent.planner._windows_inspection",
        return_value="existing ACL",
    ):
        with patch("permission_agent.planner.subprocess.run") as run:
            with patch("builtins.print"):
                report = plan_permission_change(
                    make_request(), system="Windows"
                )

    run.assert_not_called()
    assert report["permissions_changed"] is False


def test_windows_acl_analysis_flags_full_control():
    from permission_agent.planner import _analyze_acl

    acl = (
        r"C:\ACL-Test NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)"
        "\nBUILTIN\\Administrators:(I)(OI)(CI)(F)"
    )

    analysis = _analyze_acl(acl, "IIS_IUSRS", "Windows")

    assert len(analysis["potential_write_conflicts"]) == 2
    assert analysis["policy_verified"] is False


def test_windows_acl_analysis_does_not_flag_read_execute():
    from permission_agent.planner import _analyze_acl

    acl = r"C:\ACL-Test BUILTIN\Users:(RX)"

    analysis = _analyze_acl(acl, "IIS_IUSRS", "Windows")

    assert analysis["potential_write_conflicts"] == []
    assert analysis["policy_verified"] is False


def test_linux_acl_analysis_flags_write_permission():
    from permission_agent.planner import _analyze_acl

    acl = (
        "user::rwx\n"
        "group::r-x\n"
        "other::r-x\n"
    )

    analysis = _analyze_acl(acl, "www-data", "Linux")

    assert len(analysis["potential_write_conflicts"]) == 1
    assert analysis["policy_verified"] is False


def test_acl_analysis_does_not_change_permissions():
    from permission_agent.planner import _analyze_acl

    acl_before = "user::rwx\ngroup::r-x\nother::r-x"

    _analyze_acl(acl_before, "www-data", "Linux")

    assert acl_before == "user::rwx\ngroup::r-x\nother::r-x"


def test_acl_analysis_requires_review_for_write_conflicts():
    from permission_agent.planner import _analyze_acl

    acl = (
        r"C:\ACL-Test BUILTIN\Users:(F)"
    )

    analysis = _analyze_acl(acl, "IIS_IUSRS", "Windows")

    assert analysis["assessment"] == "REVIEW_REQUIRED"
    assert analysis["policy_verified"] is False


def test_acl_analysis_does_not_claim_policy_verified():
    from permission_agent.planner import _analyze_acl

    acl = r"C:\ACL-Test BUILTIN\Users:(RX)"

    analysis = _analyze_acl(acl, "IIS_IUSRS", "Windows")

    assert analysis["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert analysis["policy_verified"] is False
