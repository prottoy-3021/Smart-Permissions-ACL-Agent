
"""
Native Windows AccessCheck integration.

Checks selected access rights for the current process
security token against a folder security descriptor.

READ-ONLY:
- Does not change permissions
- Does not impersonate another user
- Does not execute proposed ACL commands
"""

import ctypes
import json
import platform
import sys
from ctypes import wintypes


# Windows-specific file and directory access rights.
# These are specific access masks, not generic access bits.
ACCESS_RIGHTS = {
    "list_directory": 0x00000001,
    "create_file": 0x00000002,
    "create_subdirectory": 0x00000004,
    "read_attributes": 0x00000080,
    "write_attributes": 0x00000100,
    "write_extended_attributes": 0x00000010,
    "traverse_directory": 0x00000020,
    "delete_child": 0x00000040,
    "delete_object": 0x00010000,
    "change_permissions": 0x00040000,
    "take_ownership": 0x00080000,
}

WRITE_RELATED_RIGHTS = {
    "create_file",
    "create_subdirectory",
    "write_attributes",
    "write_extended_attributes",
    "delete_child",
    "delete_object",
    "change_permissions",
    "take_ownership",
}


class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]


def _native_access_checks(path):
    """
    Call the Windows AccessCheck API.

    The token represents the current Python process.
    The security descriptor comes from the target path.
    """
    import win32api
    import win32security

    if platform.system() != "Windows":
        raise RuntimeError(
            "Windows AccessCheck requires Windows."
        )

    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        (
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.GROUP_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION
        ),
    )

    if not descriptor.IsValid():
        raise RuntimeError(
            "The Windows security descriptor is invalid."
        )

    # pywin32 security descriptors support the buffer
    # interface. Copy the raw descriptor into stable memory.
    descriptor_buffer = ctypes.create_string_buffer(
        bytes(memoryview(descriptor))
    )

    process_token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        (
            win32security.TOKEN_QUERY
            | win32security.TOKEN_DUPLICATE
        ),
    )

    try:
        # AccessCheck requires an impersonation token.
        # Duplicating the token does not impersonate
        # another user or change process permissions.
        impersonation_token = win32security.DuplicateToken(
            process_token,
            win32security.SecurityImpersonation,
        )

        try:
            advapi32 = ctypes.WinDLL(
                "advapi32",
                use_last_error=True,
            )

            access_check = advapi32.AccessCheck

            access_check.argtypes = [
                ctypes.c_void_p,
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(GENERIC_MAPPING),
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.BOOL),
            ]

            access_check.restype = wintypes.BOOL

            # File-object generic mapping.
            mapping = GENERIC_MAPPING(
                0x00120089,  # FILE_GENERIC_READ
                0x00120116,  # FILE_GENERIC_WRITE
                0x001200A0,  # FILE_GENERIC_EXECUTE
                0x001F01FF,  # FILE_ALL_ACCESS
            )

            results = {}

            for right, mask in ACCESS_RIGHTS.items():
                privilege_buffer = (
                    ctypes.create_string_buffer(4096)
                )

                privilege_length = wintypes.DWORD(
                    len(privilege_buffer)
                )

                granted_access = wintypes.DWORD(0)
                access_status = wintypes.BOOL(0)

                ctypes.set_last_error(0)

                success = access_check(
                    descriptor_buffer,
                    wintypes.HANDLE(
                        int(impersonation_token)
                    ),
                    wintypes.DWORD(mask),
                    ctypes.byref(mapping),
                    privilege_buffer,
                    ctypes.byref(privilege_length),
                    ctypes.byref(granted_access),
                    ctypes.byref(access_status),
                )

                if not success:
                    error_code = ctypes.get_last_error()

                    raise OSError(
                        error_code,
                        ctypes.FormatError(error_code),
                    )

                results[right] = bool(
                    access_status.value
                )

            return results

        finally:
            impersonation_token.Close()

    finally:
        process_token.Close()


def analyze_current_process_access(path):
    """
    Produce a JSON-safe report from native checks.

    Successful checking does not mean the
    web-server policy has been verified.
    """
    if platform.system() != "Windows":
        raise RuntimeError(
            "This feature requires Windows."
        )

    results = _native_access_checks(path)

    write_related_grants = [
        right
        for right in WRITE_RELATED_RIGHTS
        if results.get(right, False)
    ]

    return {
        "analysis_status": "COMPLETED",
        "scope": "CURRENT_PROCESS_TOKEN_ONLY",
        "target_path": str(path),
        "access_checks": results,
        "write_related_grants": sorted(
            write_related_grants
        ),
        "write_related_grant_count": len(
            write_related_grants
        ),
        "current_token_access_check_completed": True,
        "requested_principal_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "These native Windows access checks apply "
            "only to the current process token and "
            "the target object's security descriptor. "
            "They do not prove access for IIS_IUSRS, "
            "verify the complete read-only policy, "
            "or account for every filesystem, sharing, "
            "and runtime restriction. "
            "No permissions were changed."
        ),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m "
            "permission_agent.windows_access_check "
            '"C:\\Path\\To\\Folder"'
        )
        raise SystemExit(2)

    try:
        report = analyze_current_process_access(
            sys.argv[1]
        )

        print(json.dumps(report, indent=4))

    except Exception as exc:
        print("ACCESS CHECK FAILED:", exc)
        raise SystemExit(1)
