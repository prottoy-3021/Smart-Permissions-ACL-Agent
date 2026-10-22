
from permission_agent.risk_analyzer import analyze_acl_risks


def make_entry(
    principal="prottoy\\prott",
    full_control=False,
    inherited=False,
    explicit_deny=False,
    broad_principal=False,
):
    return {
        "principal": principal,
        "permissions": "(R)",
        "inherited": inherited,
        "full_control": full_control,
        "explicit_deny": explicit_deny,
        "broad_principal": broad_principal,
    }


def test_detects_full_control_as_high_risk():
    risks = analyze_acl_risks([
        make_entry(full_control=True)
    ])

    assert any(
        risk["type"] == "FULL_CONTROL"
        and risk["severity"] == "HIGH"
        for risk in risks
    )


def test_detects_inherited_permission():
    risks = analyze_acl_risks([
        make_entry(inherited=True)
    ])

    assert any(
        risk["type"] == "INHERITED_PERMISSION"
        for risk in risks
    )


def test_detects_broad_principal():
    risks = analyze_acl_risks([
        make_entry(
            principal=r"BUILTIN\Users",
            broad_principal=True,
        )
    ])

    assert any(
        risk["type"] == "BROAD_PRINCIPAL"
        and risk["severity"] == "HIGH"
        for risk in risks
    )


def test_empty_entries_produce_no_risks():
    assert analyze_acl_risks([]) == []


def test_detects_multiple_risks():
    risks = analyze_acl_risks([
        make_entry(
            full_control=True,
            inherited=True,
        )
    ])

    risk_types = {risk["type"] for risk in risks}

    assert "FULL_CONTROL" in risk_types
    assert "INHERITED_PERMISSION" in risk_types

