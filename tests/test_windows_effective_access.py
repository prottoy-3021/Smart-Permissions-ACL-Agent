
from permission_agent.windows_effective_access import (
    parse_icacls_output,
    analyze_windows_acl,
)


SAMPLE_ACL = r"""
C:\ACL-Test NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(F)
            PROTTOY\prott:(I)(OI)(CI)(F)
Successfully processed 1 files; Failed processing 0 files
"""


def test_parse_three_acl_entries():
    entries = parse_icacls_output(SAMPLE_ACL)
    assert len(entries) == 3


def test_detect_full_control():
    entries = parse_icacls_output(SAMPLE_ACL)
    assert all(entry["potential_write"] for entry in entries)


def test_detect_inherited_permissions():
    entries = parse_icacls_output(SAMPLE_ACL)
    assert all(entry["inherited"] for entry in entries)


def test_detect_three_potential_conflicts():
    result = analyze_windows_acl(SAMPLE_ACL)
    assert result["conflict_count"] == 3


def test_policy_is_not_claimed_verified():
    result = analyze_windows_acl(SAMPLE_ACL)
    assert result["policy_verified"] is False


def test_empty_acl_requires_more_evidence():
    result = analyze_windows_acl("")
    assert result["assessment"] == "INSUFFICIENT_EVIDENCE"


def test_first_principal_excludes_folder_path():
    acl = (
        r"C:\ACL-Test NT AUTHORITY\SYSTEM:(I)(F)"
    )

    entries = parse_icacls_output(
        acl,
        target_path=r"C:\ACL-Test",
    )

    assert len(entries) == 1
    assert entries[0]["principal"] == (
        r"NT AUTHORITY\SYSTEM"
    )


def test_path_with_spaces_is_removed():
    acl = (
        r"C:\My Test Folder BUILTIN\Users:(RX)"
    )

    entries = parse_icacls_output(
        acl,
        target_path=r"C:\My Test Folder",
    )

    assert entries[0]["principal"] == (
        r"BUILTIN\Users"
    )


def test_deny_entry_is_identified():
    acl = r"C:\ACL-Test BUILTIN\Users:(DENY)(W)"

    result = analyze_windows_acl(
        acl,
        target_path=r"C:\ACL-Test",
    )

    assert result["deny_count"] == 1
    assert result["conflict_count"] == 0
    assert result["entries"][0]["denied"] is True
    assert result["policy_verified"] is False


def test_inherited_acl_entries_are_counted():
    acl = (
        r"C:\ACL-Test NT AUTHORITY\SYSTEM:(I)(F)"
        "\n"
        r"BUILTIN\Users:(I)(RX)"
    )

    result = analyze_windows_acl(
        acl,
        target_path=r"C:\ACL-Test",
    )

    assert result["inherited_count"] == 2
    assert result["conflict_count"] == 1
