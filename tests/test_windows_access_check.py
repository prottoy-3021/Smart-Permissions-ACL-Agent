
from unittest.mock import patch

import pytest

from permission_agent.windows_access_check import (
    ACCESS_RIGHTS,
    WRITE_RELATED_RIGHTS,
    analyze_current_process_access,
)


TEST_PATH = r"C:\ACL-Test"


def mock_access_report(results):
    with patch(
        "permission_agent.windows_access_check.platform.system",
        return_value="Windows",
    ):
        with patch(
            "permission_agent.windows_access_check._native_access_checks",
            return_value=results,
        ):
            return analyze_current_process_access(
                TEST_PATH
            )


def test_access_rights_defined():
    assert "list_directory" in ACCESS_RIGHTS
    assert "create_file" in ACCESS_RIGHTS
    assert "delete_object" in ACCESS_RIGHTS


def test_read_only_results():
    report = mock_access_report({
        "list_directory": True,
        "traverse_directory": True,
        "create_file": False,
        "create_subdirectory": False,
        "delete_object": False,
    })

    assert report["access_checks"][
        "list_directory"
    ] is True

    assert report["write_related_grant_count"] == 0


def test_detect_create_file_access():
    report = mock_access_report({
        "list_directory": True,
        "create_file": True,
    })

    assert "create_file" in (
        report["write_related_grants"]
    )


def test_detect_multiple_write_related_rights():
    report = mock_access_report({
        "create_file": True,
        "delete_object": True,
        "change_permissions": True,
    })

    assert report["write_related_grant_count"] == 3


def test_no_rights_granted():
    results = {
        right: False
        for right in ACCESS_RIGHTS
    }

    report = mock_access_report(results)

    assert report["write_related_grant_count"] == 0


def test_write_related_rights_are_defined():
    assert "delete_object" in WRITE_RELATED_RIGHTS
    assert "change_permissions" in WRITE_RELATED_RIGHTS


def test_reject_non_windows():
    with patch(
        "permission_agent.windows_access_check.platform.system",
        return_value="Linux",
    ):
        with pytest.raises(RuntimeError):
            analyze_current_process_access(
                TEST_PATH
            )


def test_policy_remains_unverified():
    report = mock_access_report({
        "list_directory": True,
        "create_file": True,
    })

    assert (
        report["current_token_access_check_completed"]
        is True
    )

    assert (
        report["requested_principal_access_verified"]
        is False
    )

    assert report["policy_verified"] is False
    assert report["permissions_changed"] is False
