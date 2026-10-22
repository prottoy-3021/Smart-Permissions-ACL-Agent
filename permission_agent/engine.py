
import platform

from permission_agent.validator import validate_request
from permission_agent.planner import plan_permission_change


def execute_request(request, apply=False):
    """
    Validate requests and safely generate a permission plan.

    Real permission changes are disabled.
    Linux execution remains blocked until its analysis is verified.
    """

    # Never allow permission-changing mode.
    if apply:
        print(
            "Permission-changing mode is disabled. "
            "No permissions were changed."
        )
        return False

    # Validate the request.
    try:
        validated_request = validate_request(request)
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print(f"REQUEST REJECTED: {exc}")
        print("No permissions were changed.")
        return False

    system = platform.system()

    # Linux remains blocked until its analysis is verified.
    if system == "Linux":
        print("Linux permission analysis is not yet verified.")
        print("Request BLOCKED. No permissions were changed.")
        return False

    if system != "Windows":
        print(f"Request BLOCKED: Unsupported operating system: {system}")
        print("No permissions were changed.")
        return False

    # Generate a plan on Windows, but do not execute its commands.
    try:
        report = plan_permission_change(
            validated_request,
            system=system,
        )
    except Exception as exc:
        print(f"ACL INSPECTION FAILED: {exc}")
        print("Request BLOCKED. No permissions were changed.")
        return False

    # Support the old test contract and reject invalid reports.
    if not isinstance(report, dict) or report.get("decision") != "PLAN_ONLY":
        print("Request BLOCKED: A verified permission plan was not produced.")
        print("No permissions were changed.")
        return False

    if report.get("permissions_changed") is not False:
        print("Request BLOCKED: Unexpected permission-change status.")
        print("No permissions were changed.")
        return False

    print("Plan generated for review only.")
    print("No permissions were changed.")
    return True
