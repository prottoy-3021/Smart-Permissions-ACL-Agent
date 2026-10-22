from permission_agent.acl_parser import parse_acl_entries


def test_parses_inherited_full_control():
    output = r"PROTTOY\prott:(I)(OI)(CI)(F)"

    entries = parse_acl_entries(output)

    assert len(entries) == 1
    assert entries[0]["principal"] == r"PROTTOY\prott"
    assert entries[0]["inherited"] is True
    assert entries[0]["full_control"] is True


def test_detects_broad_principal():
    output = r"BUILTIN\Users:(I)(OI)(CI)(RX)"

    entries = parse_acl_entries(output)

    assert len(entries) == 1
    assert entries[0]["broad_principal"] is True


def test_handles_empty_output():
    assert parse_acl_entries("") == []


def test_ignores_icacls_summary():
    output = (
        r"PROTTOY\prott:(R)"
        "\nSuccessfully processed 1 files; Failed processing 0 files"
    )

    entries = parse_acl_entries(output)

    assert len(entries) == 1
    assert entries[0]["principal"] == r"PROTTOY\prott"


def test_detects_explicit_deny_marker():
    output = r"PROTTOY\prott:(DENY)(W)"

    entries = parse_acl_entries(output)

    assert len(entries) == 1
    assert entries[0]["explicit_deny"] is True
