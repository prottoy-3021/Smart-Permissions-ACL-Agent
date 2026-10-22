
"""
Native Windows ACL inspection using pywin32.

Read-only: no ACL or permission changes.
This module does not calculate effective access.
"""

import platform


# Windows access-mask bits that can indicate
# writing, deletion, or permission modification.
WRITE_CAPABLE_MASK = (
    0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000040  # FILE_DELETE_CHILD
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x40000000  # GENERIC_WRITE
    | 0x10000000  # GENERIC_ALL
)

INHERITED_ACE = 0x10
INHERIT_ONLY_ACE = 0x08


def inspect_native_windows_acl(path):
    """
    Retrieve a Windows file/directory security descriptor.

    Reports direct ACE information but does not
    determine effective permissions.
    """
    if platform.system() != "Windows":
        raise RuntimeError(
            "Native Windows ACL inspection requires Windows."
        )

    import win32security

    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        (
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.GROUP_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION
        ),
    )

    owner = descriptor.GetSecurityDescriptorOwner()
    group = descriptor.GetSecurityDescriptorGroup()
    dacl = descriptor.GetSecurityDescriptorDacl()

    owner_sid = (
        win32security.ConvertSidToStringSid(owner)
        if owner is not None else None
    )

    group_sid = (
        win32security.ConvertSidToStringSid(group)
        if group is not None else None
    )

    entries = []

    if dacl is not None:
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)

            ace_type = ace[0][0]
            ace_flags = ace[0][1]
            access_mask = ace[1]

            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                entry_type = "ALLOW"

            elif ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
                entry_type = "DENY"

            else:
                entry_type = "OTHER"

            # Standard allow/deny ACEs have the SID
            # at index 2. Other formats require
            # specialized decoding.
            sid_string = None

            if entry_type in ("ALLOW", "DENY"):
                sid_string = (
                    win32security.ConvertSidToStringSid(
                        ace[2]
                    )
                )

            inherited = bool(
                ace_flags & INHERITED_ACE
            )

            inherit_only = bool(
                ace_flags & INHERIT_ONLY_ACE
            )

            has_write_mask = bool(
                access_mask & WRITE_CAPABLE_MASK
            )

            entries.append({
                "index": index,
                "type": entry_type,
                "sid": sid_string,
                "mask": hex(access_mask),
                "inherited": inherited,
                "inherit_only": inherit_only,
                "has_write_mask": has_write_mask,
                "potential_write_grant": (
                    entry_type == "ALLOW"
                    and has_write_mask
                    and not inherit_only
                ),
            })

    write_candidates = [
        entry for entry in entries
        if entry["potential_write_grant"]
    ]

    deny_entries = [
        entry for entry in entries
        if entry["type"] == "DENY"
    ]

    inherited_entries = [
        entry for entry in entries
        if entry["inherited"]
    ]

    unsupported_entries = [
        entry for entry in entries
        if entry["type"] == "OTHER"
    ]

    return {
        "inspection_status": "COMPLETED",
        "scope": "NATIVE_SECURITY_DESCRIPTOR",
        "target_path": str(path),
        "owner_sid": owner_sid,
        "group_sid": group_sid,
        "null_dacl": dacl is None,
        "ace_count": len(entries),
        "entries": entries,
        "potential_write_grant_count": len(
            write_candidates
        ),
        "deny_count": len(deny_entries),
        "inherited_count": len(inherited_entries),
        "unsupported_ace_count": len(
            unsupported_entries
        ),
        "effective_access_verified": False,
        "policy_verified": False,
        "permissions_changed": False,
        "note": (
            "Native ACL inspection only. A NULL DACL "
            "permits broad access and must be treated "
            "as a critical security finding. "
            "An empty DACL normally denies access. "
            "ACE ordering, user tokens, ownership, "
            "group membership, and authorization "
            "semantics require further verification."
        ),
    }
