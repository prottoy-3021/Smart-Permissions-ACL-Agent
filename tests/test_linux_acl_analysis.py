
from permission_agent.linux_acl_analysis import (
    parse_linux_acl,
    analyze_linux_acl,
)


SAMPLE_ACL = """\
# file: /tmp/acl-test
# owner: alice
# group: developers
user::rwx
user:bob:rwx                  #effective:r-x
group::rwx                   #effective:r-x
group:developers:r-x
mask::r-x
other::r-x
default:user::rwx
default:user:bob:rwx          #effective:r-x
default:group::r-x
default:mask::r-x
default:other::---
"""


def find_entry(entries, scope, kind, name=""):
    return next(
        entry for entry in entries
        if entry["scope"] == scope
        and entry["type"] == kind
        and entry["name"] == name
    )


def test_parse_linux_acl():
    result = parse_linux_acl(SAMPLE_ACL)

    assert len(result["entries"]) == 11
    assert result["metadata"]["owner"] == "alice"


def test_named_user_mask_applied():
    result = parse_linux_acl(SAMPLE_ACL)

    bob = find_entry(
        result["entries"], "access", "user", "bob"
    )

    assert bob["effective_permissions"] == "r-x"
    assert bob["mask_applied"] is True


def test_owning_group_mask_applied():
    result = parse_linux_acl(SAMPLE_ACL)

    group = find_entry(
        result["entries"], "access", "group"
    )

    assert group["effective_permissions"] == "r-x"


def test_owner_not_restricted_by_mask():
    result = parse_linux_acl(SAMPLE_ACL)

    owner = find_entry(
        result["entries"], "access", "user"
    )

    assert owner["effective_permissions"] == "rwx"
    assert owner["mask_applied"] is False


def test_other_not_restricted_by_mask():
    result = parse_linux_acl(SAMPLE_ACL)

    other = find_entry(
        result["entries"], "access", "other"
    )

    assert other["effective_permissions"] == "r-x"
    assert other["mask_applied"] is False


def test_default_acl_entries_separated():
    report = analyze_linux_acl(SAMPLE_ACL)

    assert report["access_entry_count"] == 6
    assert report["default_entry_count"] == 5


def test_default_named_user_mask():
    result = parse_linux_acl(SAMPLE_ACL)

    bob = find_entry(
        result["entries"], "default", "user", "bob"
    )

    assert bob["effective_permissions"] == "r-x"


def test_detect_owner_write_access():
    report = analyze_linux_acl(SAMPLE_ACL)

    assert report["access_write_count"] == 1

    assert report["access_write_entries"][0][
        "type"
    ] == "user"


def test_malformed_acl_is_incomplete():
    report = analyze_linux_acl(
        "user:alice:invalid"
    )

    assert report["analysis_status"] == "INCOMPLETE"
    assert len(report["parse_errors"]) > 0


def test_missing_named_user_mask_detected():
    acl = """\
user::rwx
user:bob:rwx
group::r-x
other::r--
"""

    report = analyze_linux_acl(acl)

    assert report["analysis_status"] == "INCOMPLETE"

    assert any(
        "require a mask" in error["reason"]
        for error in report["parse_errors"]
    )


def test_basic_permissions_without_mask():
    acl = """\
user::rwx
group::r-x
other::r--
"""

    report = analyze_linux_acl(acl)

    assert report["analysis_status"] == "COMPLETED"


def test_empty_acl_rejected_as_incomplete():
    report = analyze_linux_acl("")

    assert report["analysis_status"] == "INCOMPLETE"


def test_mask_limits_write_access():
    acl = """\
user::r-x
user:bob:rwx
group::r-x
mask::r-x
other::r-x
"""

    report = analyze_linux_acl(acl)

    assert report["access_write_count"] == 0


def test_never_claims_policy_verified():
    report = analyze_linux_acl(SAMPLE_ACL)

    assert report["effective_access_verified"] is False
    assert report["policy_verified"] is False
    assert report["permissions_changed"] is False
