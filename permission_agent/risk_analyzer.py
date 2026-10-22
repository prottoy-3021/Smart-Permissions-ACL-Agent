
def analyze_acl_risks(entries):
    """
    Classify risks found in parsed ACL entries.
    This function is read-only.
    """

    risks = []

    for entry in entries:
        principal = entry["principal"]

        if entry["full_control"]:
            risks.append({
                "severity": "HIGH",
                "type": "FULL_CONTROL",
                "principal": principal,
                "message": (
                    f"{principal} has a Full Control ACL entry."
                ),
            })

        if entry["inherited"]:
            risks.append({
                "severity": "MEDIUM",
                "type": "INHERITED_PERMISSION",
                "principal": principal,
                "message": (
                    f"{principal} has an inherited permission entry."
                ),
            })

        if entry["explicit_deny"]:
            risks.append({
                "severity": "MEDIUM",
                "type": "EXPLICIT_DENY",
                "principal": principal,
                "message": (
                    f"{principal} has an explicit deny marker."
                ),
            })

        if entry["broad_principal"]:
            risks.append({
                "severity": "HIGH",
                "type": "BROAD_PRINCIPAL",
                "principal": principal,
                "message": (
                    f"{principal} is a broad principal; "
                    "review its permissions and scope."
                ),
            })

    return risks
