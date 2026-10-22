
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from permission_agent.windows_native_acl import (
    inspect_native_windows_acl,
)


TEST_PATH = r"C:\ACL-Test"


def run_mock_inspection(aces=None, null_dacl=False):
    """
    Mock the Windows security descriptor API.

    Tests run without changing real folder permissions.
    """
    if aces is None:
        aces = []

    dacl = None

    if not null_dacl:
        dacl = Mock()
        dacl.GetAceCount.return_value = len(aces)
        dacl.GetAce.side_effect = lambda i: aces[i]

    descriptor = Mock()
    descriptor.GetSecurityDescriptorOwner.return_value = "owner"
    descriptor.GetSecurityDescriptorGroup.return_value = "group"
    descriptor.GetSecurityDescriptorDacl.return_value = dacl

    fake_win32security = SimpleNamespace(
        SE_FILE_OBJECT=1,
        OWNER_SECURITY_INFORMATION=1,
        GROUP_SECURITY_INFORMATION=2,
        DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_DENIED_ACE_TYPE=1,
        GetNamedSecurityInfo=Mock(return_value=descriptor),
        ConvertSidToStringSid=lambda sid: f"SID-{sid}",
    )

    with patch(
        "permission_agent.windows_native_acl.platform.system",
        return_value="Windows",
    ):
        with patch.dict(
            sys.modules,
            {"win32security": fake_win32security},
        ):
            return inspect_native_windows_acl(TEST_PATH)


def test_detect_allow_ace():
    report = run_mock_inspection([
        ((0, 0), 0x00000002, "user")
    ])

    assert report["ace_count"] == 1
    assert report["entries"][0]["type"] == "ALLOW"


def test_detect_write_permission():
    report = run_mock_inspection([
        ((0, 0), 0x00000002, "user")
    ])

    assert report["potential_write_grant_count"] == 1


def test_detect_deny_ace():
    report = run_mock_inspection([
        ((1, 0), 0x00000002, "user")
    ])

    assert report["deny_count"] == 1
    assert report["potential_write_grant_count"] == 0


def test_detect_inherited_ace():
    report = run_mock_inspection([
        ((0, 0x10), 0x00000001, "user")
    ])

    assert report["inherited_count"] == 1
    assert report["entries"][0]["inherited"] is True


def test_inherit_only_is_not_current_object_grant():
    report = run_mock_inspection([
        ((0, 0x08), 0x00000002, "user")
    ])

    assert report["potential_write_grant_count"] == 0
    assert report["entries"][0]["inherit_only"] is True


def test_detect_null_dacl():
    report = run_mock_inspection(null_dacl=True)

    assert report["null_dacl"] is True
    assert report["ace_count"] == 0
    assert report["policy_verified"] is False


def test_reject_non_windows():
    with patch(
        "permission_agent.windows_native_acl.platform.system",
        return_value="Linux",
    ):
        with pytest.raises(RuntimeError):
            inspect_native_windows_acl(TEST_PATH)


def test_never_claim_verified_access():
    report = run_mock_inspection([
        ((0, 0), 0x00000001, "user")
    ])

    assert report["effective_access_verified"] is False
    assert report["policy_verified"] is False
    assert report["permissions_changed"] is False
