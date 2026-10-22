
import json
import os
import platform
import shlex
import shutil
import subprocess

from permission_agent.windows_effective_access import analyze_windows_acl
from permission_agent.windows_identity import inspect_current_windows_identity
from permission_agent.windows_token_analysis import analyze_token_acl_overlap
from permission_agent.windows_sid_analysis import analyze_acl_sid_membership
from permission_agent.windows_native_acl import inspect_native_windows_acl
from permission_agent.windows_access_check import (
    analyze_current_process_access,
)
from permission_agent.windows_policy_audit import (
    audit_read_only_policy,
    resolve_windows_sid,
)
from permission_agent.linux_acl_analysis import analyze_linux_acl

# ============================================================
# 1. WINDOWS ACL INSPECTION
# ============================================================

def _windows_inspection(path):
    """
    Read existing Windows ACLs using icacls.

    This function performs inspection only.
    It does not change permissions.
    """

    result = subprocess.run(
        ["icacls", path],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr
            or result.stdout
            or "icacls inspection failed"
        )

    return result.stdout


# ============================================================
# 2. LINUX ACL INSPECTION
# ============================================================

def _linux_inspection(path):
    """
    Read existing Linux ACLs using getfacl.

    This function does not modify permissions.
    """

    if shutil.which("getfacl") is None:
        raise RuntimeError(
            "getfacl is not installed; "
            "Linux ACL inspection is unavailable."
        )

    result = subprocess.run(
        ["getfacl", "--", path],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr
            or result.stdout
            or "getfacl inspection failed"
        )

    return result.stdout


# ============================================================
# 3. PRELIMINARY ACL ANALYSIS
# ============================================================

def _analyze_acl(existing_permissions, web_server, system):
    """
    Analyze existing ACL entries.

    Identify:
    - Possible web-server permissions
    - Potential write-capable permissions
    - Privileged accounts requiring review
    - Possible security conflicts

    This is preliminary analysis only.
    """

    findings = []
    web_server_entries = []
    trusted_entries_for_review = []

    write_markers = (
        "(F)",
        "(M)",
        "(W)",
        "(WD)",
        "(AD)",
        "(DC)",
    )

    for line in existing_permissions.splitlines():

        entry = line.strip()

        if not entry or "Successfully processed" in entry:
            continue

        # ----------------------------------------------------
        # WINDOWS ACL ANALYSIS
        # ----------------------------------------------------

        if system == "Windows":

            upper_entry = entry.upper()
            principal_upper = web_server.upper()

            # Identify possible web-server ACL entries.
            if principal_upper in upper_entry:

                web_server_entries.append({
                    "entry": entry,
                    "finding": (
                        "Possible web-server ACL entry found. "
                        "Verify its effective permissions."
                    ),
                })

            # Identify potentially write-capable permissions.
            if any(
                marker in upper_entry
                for marker in write_markers
            ):

                findings.append({
                    "entry": entry,
                    "finding": (
                        "Potential write-capable permission found. "
                        "Review the principal, inheritance, "
                        "and effective access."
                    ),
                })

                # Privileged Windows accounts require review.
                if (
                    "NT AUTHORITY\\SYSTEM" in upper_entry
                    or "BUILTIN\\ADMINISTRATORS" in upper_entry
                ):

                    trusted_entries_for_review.append(entry)

        # ----------------------------------------------------
        # LINUX ACL ANALYSIS
        # ----------------------------------------------------

        elif system == "Linux":

            if entry.startswith("#"):
                continue

            permission_entry = entry

            # Inspect default ACL entries.
            if permission_entry.startswith("default:"):

                permission_entry = permission_entry[
                    len("default:"):
                ]

            parts = permission_entry.split(":")

            if len(parts) < 3:
                continue

            permissions = parts[-1].strip()

            # Detect potentially write-capable entries.
            if "w" in permissions:

                findings.append({
                    "entry": entry,
                    "finding": (
                        "Potential write-capable ACL entry found. "
                        "Review ACL masks, groups, and inheritance."
                    ),
                })

            # Identify named web-server user entries.
            if (
                parts[0] == "user"
                and parts[1].casefold() == web_server.casefold()
            ):

                web_server_entries.append({
                    "entry": entry,
                    "finding": (
                        "Possible web-server ACL entry found. "
                        "Verify effective access and the ACL mask."
                    ),
                })

    # --------------------------------------------------------
    # DETERMINE PRELIMINARY ASSESSMENT
    # --------------------------------------------------------

    if findings:

        assessment = "REVIEW_REQUIRED"

    elif not web_server_entries:

        assessment = "INSUFFICIENT_EVIDENCE"

    else:

        assessment = "POLICY_NOT_VERIFIED"

    return {
        "web_server_principal": web_server,
        "web_server_entries": web_server_entries,
        "potential_write_conflicts": findings,
        "trusted_entries_for_review": trusted_entries_for_review,
        "assessment": assessment,
        "policy_verified": False,
        "note": (
            "Preliminary ACL analysis only. "
            "This does not fully resolve Windows group membership, "
            "deny entries, inherited permissions, Linux ACL masks, "
            "or effective access. "
            "No permissions were changed."
        ),
    }


# ============================================================
# 4. WINDOWS PERMISSION PLAN GENERATION
# ============================================================

def _windows_plan(path, web_server):
    """
    Generate proposed Windows ACL commands.

    Commands are returned as data only.
    No permission-changing commands are executed.
    """

    return [
        {
            "purpose": (
                "Propose read and execute access "
                "for the web-server group"
            ),
            "command": [
                "icacls",
                path,
                "/grant",
                f"{web_server}:(OI)(CI)(RX)",
            ],
            "executed": False,
        },
        {
            "purpose": (
                "Review potential write-access conflicts "
                "before finalizing the read-only policy"
            ),
            "command": None,
            "executed": False,
            "note": (
                "No permissions are removed or denied automatically. "
                "Inherited permissions, group memberships, and "
                "effective access must be reviewed before "
                "any change is authorized."
            ),
        },
    ]


# ============================================================
# 5. LINUX PERMISSION PLAN GENERATION
# ============================================================

def _linux_plan(path, web_server):
    """
    Generate proposed Linux ACL commands.

    The commands are never executed.
    """

    grant_command = [
        "setfacl",
        "-m",
        f"u:{web_server}:r-x",
        "--",
        path,
    ]

    return [
        {
            "purpose": (
                "Propose read and directory-traverse access "
                "for the web server"
            ),
            "command": grant_command,
            "display": shlex.join(grant_command),
            "executed": False,
        },
        {
            "purpose": (
                "Review potential write-access conflicts "
                "before finalizing the read-only policy"
            ),
            "command": None,
            "executed": False,
            "note": (
                "User, group, default ACL, ACL mask, and "
                "directory permissions require review. "
                "No changes are applied."
            ),
        },
    ]


# ============================================================
# 6. WINDOWS IDENTITY INSPECTION
# ============================================================

def _optional_windows_identity_inspection(report, system):
    """
    Optionally inspect the current Windows process identity.

    Identity inspection is enabled only when:
        SMART_PERMISSIONS_INSPECT_IDENTITY=1

    This function:
    - Retrieves the current process user and groups
    - Adds the identity information to the report
    - Does not modify permissions
    - Does not calculate effective access
    """

    if system != "Windows":
        return report

    if os.environ.get(
        "SMART_PERMISSIONS_INSPECT_IDENTITY"
    ) != "1":
        return report

    try:

        identity_report = (
            inspect_current_windows_identity()
        )

        report["identity_inspection"] = identity_report

    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as exc:

        report["identity_inspection"] = {
            "inspection_status": "FAILED",
            "reason": str(exc),
            "effective_access_verified": False,
            "permissions_changed": False,
        }

    return report


# ============================================================
# 7. MAIN PERMISSION PLANNING FUNCTION
# ============================================================

def plan_permission_change(request, system=None):
    """
    Inspect existing permissions and generate a
    platform-specific permission plan.

    Windows functionality:
    - Inspect existing ACL entries
    - Perform preliminary permission analysis
    - Perform structured ACL analysis
    - Optionally inspect current user and groups
    - Generate proposed permission commands

    Linux functionality:
    - Inspect existing ACL entries where supported
    - Perform preliminary analysis
    - Generate proposed permission commands

    Safety guarantee:
    Permission-changing commands are never executed.
    """

    # --------------------------------------------------------
    # EXTRACT REQUEST DETAILS
    # --------------------------------------------------------

    path = request["path"]

    principal = request.get(
        "web_server_principal",
        request["principal"],
    )

    system = system or platform.system()

    # --------------------------------------------------------
    # VALIDATE SUPPORTED POLICY
    # --------------------------------------------------------

    if request.get("policy") != (
        "web_server_and_read_only_others"
    ):

        report = {
            "target_path": path,
            "principal": principal,
            "decision": "BLOCKED",
            "reason": (
                "Only the original www permission policy "
                "is handled by this planner."
            ),
            "permissions_changed": False,
        }

        print(json.dumps(report, indent=4))

        return report

    # --------------------------------------------------------
    # PLATFORM-SPECIFIC ACL INSPECTION
    # --------------------------------------------------------

    try:

        if system == "Windows":

            existing_permissions = _windows_inspection(path)

            proposed_plan = _windows_plan(
                path,
                principal,
            )

        elif system == "Linux":

            existing_permissions = _linux_inspection(path)

            proposed_plan = _linux_plan(
                path,
                principal,
            )

        else:

            raise RuntimeError(
                f"Unsupported operating system: {system}"
            )

        # ----------------------------------------------------
        # ORIGINAL PRELIMINARY ACL ANALYSIS
        # ----------------------------------------------------

        acl_analysis = _analyze_acl(
            existing_permissions,
            principal,
            system,
        )

        # ----------------------------------------------------
        # STRUCTURED WINDOWS ACL ANALYSIS
        # ----------------------------------------------------

        if system == "Windows":

            structured_analysis = analyze_windows_acl(
                existing_permissions,
                target_path=path,
            )

            acl_analysis["structured_acl_analysis"] = (
                structured_analysis
            )

        # No permission-changing commands are executed.

        
        # ====================================================
        # STRUCTURED LINUX ACL ANALYSIS
        # ====================================================

        if system == "Linux":
            linux_analysis = analyze_linux_acl(
                existing_permissions
            )

            acl_analysis["structured_linux_acl_analysis"] = (
                linux_analysis
            )

    

    # --------------------------------------------------------
    # HANDLE ACL INSPECTION ERRORS
    # --------------------------------------------------------

    except (OSError, RuntimeError) as exc:

        report = {
            "target_path": path,
            "web_server_principal": principal,
            "analysis_status": "INSPECTION_FAILED",
            "decision": "BLOCKED",
            "reason": str(exc),
            "permissions_changed": False,
        }

        print("\nPERMISSION PLAN - NO CHANGES APPLIED")

        print(json.dumps(report, indent=4))

        return report

    # --------------------------------------------------------
    # GENERATE FINAL PERMISSION REPORT
    # --------------------------------------------------------

    report = {
        "target_path": path,

        "web_server_principal": principal,

        "policy": "web_server_and_read_only_others",

        "analysis_status": "INSPECTED",

        "existing_permissions": existing_permissions,

        "acl_analysis": acl_analysis,

        "proposed_plan": proposed_plan,

        "decision": "PLAN_ONLY",

        "permissions_changed": False,

        "policy_verified": False,

        "warning": (
            "This is a proposal, not proof of effective "
            "read-only access. "
            "Potential write-capable entries are flagged "
            "for review. "
            "Inherited permissions, group memberships, "
            "and platform-specific ACL behavior must be "
            "analyzed before the policy can be verified."
        ),
    }

    # --------------------------------------------------------
    # OPTIONAL WINDOWS USER AND GROUP INSPECTION
    # --------------------------------------------------------

    
    report = _optional_windows_identity_inspection(
        report,
        system,
    )

    # ========================================================
    # MATCH CURRENT WINDOWS TOKEN AGAINST VISIBLE ACL ENTRIES
    # ========================================================

    if (
        system == "Windows"
        and report.get(
            "identity_inspection", {}
        ).get("inspection_status") == "COMPLETED"
    ):
        report["token_acl_overlap"] = (
            analyze_token_acl_overlap(
                report["acl_analysis"][
                    "structured_acl_analysis"
                ],
                report["identity_inspection"],
            )
        )

        # ========================================================
    # WINDOWS SID MEMBERSHIP ANALYSIS
    # ========================================================

    if (
        system == "Windows"
        and report.get(
            "identity_inspection", {}
        ).get("inspection_status") == "COMPLETED"
    ):
        try:
            report["sid_membership_analysis"] = (
                analyze_acl_sid_membership(
                    report["acl_analysis"][
                        "structured_acl_analysis"
                    ]
                )
            )

        except (OSError, RuntimeError, ValueError) as exc:
            report["sid_membership_analysis"] = {
                "analysis_status": "FAILED",
                "reason": str(exc),
                "effective_access_verified": False,
                "policy_verified": False,
                "permissions_changed": False,
            }


    
    # ========================================================
    # NATIVE WINDOWS SECURITY DESCRIPTOR INSPECTION
    # ========================================================

    if (
        system == "Windows"
        and os.environ.get(
            "SMART_PERMISSIONS_INSPECT_IDENTITY"
        ) == "1"
    ):
        try:
            report["native_acl_inspection"] = (
                inspect_native_windows_acl(path)
            )

        except Exception as exc:
            # Optional diagnostics must never authorize
            # permission changes or block the safe plan.
            report["native_acl_inspection"] = {
                "inspection_status": "FAILED",
                "reason": str(exc),
                "effective_access_verified": False,
                "policy_verified": False,
                "permissions_changed": False,
            }

    
    # ========================================================
    # OPTIONAL NATIVE WINDOWS ACCESSCHECK
    # ========================================================

    if (
        system == "Windows"
        and os.environ.get(
            "SMART_PERMISSIONS_ACCESS_CHECK"
        ) == "1"
    ):
        try:
            report["windows_access_check"] = (
                analyze_current_process_access(path)
            )

        except Exception as exc:
            report["windows_access_check"] = {
                "analysis_status": "FAILED",
                "reason": str(exc),
                "current_token_access_check_completed": False,
                "requested_principal_access_verified": False,
                "policy_verified": False,
                "permissions_changed": False,
            }

    
    # ========================================================
    # OPTIONAL WINDOWS READ-ONLY POLICY AUDIT
    # ========================================================

    if (
        system == "Windows"
        and os.environ.get(
            "SMART_PERMISSIONS_POLICY_AUDIT"
        ) == "1"
    ):
        try:
            # Reuse existing native inspection if available.
            native_report = report.get(
                "native_acl_inspection"
            )

            if (
                not isinstance(native_report, dict)
                or native_report.get("inspection_status")
                != "COMPLETED"
            ):
                native_report = (
                    inspect_native_windows_acl(path)
                )

                report["native_acl_inspection"] = (
                    native_report
                )

            # Resolve the target principal's SID.
            # Failure must not be interpreted as permission
            # approval or policy verification.
            target_sid = None
            resolution_error = None

            try:
                target_sid = resolve_windows_sid(
                    principal
                )
            except (
                OSError,
                RuntimeError,
                ValueError,
            ) as exc:
                resolution_error = str(exc)

            policy_audit = audit_read_only_policy(
                native_report,
                target_principal=principal,
                target_sid=target_sid,
            )

            if resolution_error:
                policy_audit[
                    "principal_resolution_error"
                ] = resolution_error

            report["read_only_policy_audit"] = (
                policy_audit
            )

        except Exception as exc:
            # Optional analysis failures must not authorize
            # permission changes or claim policy compliance.
            report["read_only_policy_audit"] = {
                "audit_status": "FAILED",
                "reason": str(exc),
                "policy_verified": False,
                "permissions_changed": False,
            }

    # The full requested policy remains unverified.
    report["policy_verified"] = False




    # --------------------------------------------------------
    # DISPLAY FINAL REPORT
    # --------------------------------------------------------

    print("\nPERMISSION PLAN - NO CHANGES APPLIED")

    print(json.dumps(report, indent=4))

    return report
