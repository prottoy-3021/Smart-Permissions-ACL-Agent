
import pytest

from permission_agent.parser import parse_request


def test_read_only_request():
    result = parse_request(
        r"make C:\Temp\demo read-only for Alice"
    )

    assert result["path"] == r"C:\Temp\demo"
    assert result["principal"] == "Alice"
    assert result["read"] is True
    assert result["write"] is False
    assert result["execute"] is False


def test_read_write_request():
    result = parse_request(
        r"allow Alice to read and write C:\Temp\demo"
    )

    assert result["principal"] == "Alice"
    assert result["read"] is True
    assert result["write"] is True


def test_reject_unknown_request():
    with pytest.raises(ValueError):
        parse_request("delete all permissions everywhere")


def test_original_www_web_server_policy():
    result = parse_request(
        r"make C:\site\www accessible to IIS_IUSRS, "
        "but read-only for everyone else"
    )

    assert result["path"] == r"C:\site\www"
    assert result["principal"] == "IIS_IUSRS"
    assert result["web_server_principal"] == "IIS_IUSRS"
    assert result["policy"] == "web_server_and_read_only_others"
    assert result["read"] is True
    assert result["write"] is False
    assert result["execute"] is True
    assert result["others_read_only"] is True


def test_alternate_www_wording():
    result = parse_request(
        r"Make the www folder at C:\site\www accessible to "
        "IIS_IUSRS with read and execute permissions, "
        "and keep everyone else read-only"
    )

    assert result["path"] == r"C:\site\www"
    assert result["principal"] == "IIS_IUSRS"
    assert result["policy"] == "web_server_and_read_only_others"


def test_www_policy_contains_proposed_command():
    result = parse_request(
        r"Make C:\site\www accessible to IIS_IUSRS, "
        "but read-only for everyone else"
    )

    assert result["proposed_command"] == [
        "icacls",
        r"C:\site\www",
        "/grant",
        "IIS_IUSRS:(OI)(CI)(RX)",
    ]


def test_www_policy_remains_plan_only():
    result = parse_request(
        r"Make C:\site\www accessible to IIS_IUSRS, "
        "but read-only for everyone else"
    )

    assert result["decision"] == "PLAN_ONLY"
    assert result["permissions_changed"] is False
    assert result["policy_verified"] is False


def test_reject_full_control_request():
    with pytest.raises(ValueError):
        parse_request(
            r"Give everyone full control of C:\site\www"
        )


def test_reject_relative_path():
    with pytest.raises(ValueError, match="absolute path"):
        parse_request(
            "make site\\www accessible to IIS_IUSRS, "
            "but read-only for everyone else"
        )
