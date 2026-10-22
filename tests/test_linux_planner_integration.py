
from unittest.mock import patch

from permission_agent.planner import plan_permission_change


LINUX_ACL = """\
# file: /tmp/acl-test
# owner: alice
# group: developers
user::rwx
user:www-data:r-x
group::r-x
mask::r-x
other::r-x
"""


def test_linux_planner_structured_analysis():
    request = {
        "path": "/tmp/acl-test",
        "principal": "www-data",
        "web_server_principal": "www-data",
        "policy": "web_server_and_read_only_others",
        "read": True,
        "write": False,
        "execute": True,
    }

    with patch(
        "permission_agent.planner._linux_inspection",
        return_value=LINUX_ACL,
    ):
        with patch("builtins.print"):
            report = plan_permission_change(
                request,
                system="Linux",
            )

    assert report["analysis_status"] == "INSPECTED"
    assert report["decision"] == "PLAN_ONLY"

    linux_analysis = report["acl_analysis"][
        "structured_linux_acl_analysis"
    ]

    assert linux_analysis["analysis_status"] == "COMPLETED"
    assert linux_analysis["access_entry_count"] == 5
    assert linux_analysis["policy_verified"] is False

    assert all(
        step["executed"] is False
        for step in report["proposed_plan"]
    )

    assert report["permissions_changed"] is False
    assert report["policy_verified"] is False
