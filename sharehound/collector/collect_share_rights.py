#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_share_rights.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

from enum import IntFlag
from typing import Union

from impacket.ldap import ldaptypes
from shareql.evaluate.evaluator import RulesEvaluator

import sharehound.kinds as kinds
from sharehound.core.Logger import Logger, TaskLogger
from sharehound.core.SMBSession import SMBSession


class AccessMaskFlags(IntFlag):
    """
    AccessMaskFlags: Enum class that defines constants for access mask flags.

    This class defines constants for various access mask flags as specified in the Microsoft documentation. These flags represent permissions or rights that can be granted or denied for security principals in access control entries (ACEs) of an access control list (ACL).

    The flags include permissions for creating or deleting child objects, listing contents, reading or writing properties, deleting a tree of objects, and controlling access. Additionally, it includes generic rights like GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE, and GENERIC_READ.

    The values for these flags are derived from the following Microsoft documentation sources:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
    - https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum

    Attributes:
        DS_CREATE_CHILD (int): Permission to create child objects.
        DS_DELETE_CHILD (int): Permission to delete child objects.
        DS_LIST_CONTENTS (int): Permission to list contents.
        DS_WRITE_PROPERTY_EXTENDED (int): Permission to write properties (extended).
        DS_READ_PROPERTY (int): Permission to read properties.
        DS_WRITE_PROPERTY (int): Permission to write properties.
        DS_DELETE_TREE (int): Permission to delete a tree of objects.
        DS_LIST_OBJECT (int): Permission to list objects.
        DS_CONTROL_ACCESS (int): Permission for access control.
        DELETE (int): Permission to delete.
        READ_CONTROL (int): Permission to read security descriptor.
        WRITE_DAC (int): Permission to modify discretionary access control list (DACL).
        WRITE_OWNER (int): Permission to change the owner.
        GENERIC_ALL (int): Generic all permissions.
        GENERIC_EXECUTE (int): Generic execute permissions.
        GENERIC_WRITE (int): Generic write permissions.
        GENERIC_READ (int): Generic read permissions.
    """

    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_LIST_CONTENTS = 0x00000004
    DS_WRITE_PROPERTY_EXTENDED = 0x00000008
    DS_READ_PROPERTY = 0x00000010
    DS_WRITE_PROPERTY = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080
    DS_CONTROL_ACCESS = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    # Generic rights
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


def collect_share_rights(
    smb_session: SMBSession,
    share_name: str,
    rules_evaluator: RulesEvaluator,
    logger: Union[Logger, TaskLogger],
):
    """
    Process share rights for a share and create corresponding edges.

    This function retrieves the security descriptor for a file or directory,
    processes the DACL to extract access rights, and creates edges between
    principals (SIDs) and the share with the appropriate share rights.

    Args:
        smb_session: The SMB session object for connecting to the share
        ogc: The opengraph context object
        share_name: The name of the share
        rules_evaluator: The rules evaluator object
        node: The share node to process rights for
        path: The path of the share
        logger: Logger object for logging operations
    """

    # Mapping of edge kinds to access mask flags
    map_rights = {
        kinds.edge_kind_can_ds_create_child: AccessMaskFlags.DS_CREATE_CHILD,
        kinds.edge_kind_can_ds_delete_child: AccessMaskFlags.DS_DELETE_CHILD,
        kinds.edge_kind_can_ds_list_contents: AccessMaskFlags.DS_LIST_CONTENTS,
        kinds.edge_kind_can_ds_write_extended_properties: AccessMaskFlags.DS_WRITE_PROPERTY_EXTENDED,
        kinds.edge_kind_can_ds_read_property: AccessMaskFlags.DS_READ_PROPERTY,
        kinds.edge_kind_can_ds_write_property: AccessMaskFlags.DS_WRITE_PROPERTY,
        kinds.edge_kind_can_ds_delete_tree: AccessMaskFlags.DS_DELETE_TREE,
        kinds.edge_kind_can_ds_list_object: AccessMaskFlags.DS_LIST_OBJECT,
        kinds.edge_kind_can_ds_control_access: AccessMaskFlags.DS_CONTROL_ACCESS,
        kinds.edge_kind_can_delete: AccessMaskFlags.DELETE,
        kinds.edge_kind_can_read_control: AccessMaskFlags.READ_CONTROL,
        kinds.edge_kind_can_write_dac: AccessMaskFlags.WRITE_DAC,
        kinds.edge_kind_can_write_owner: AccessMaskFlags.WRITE_OWNER,
        kinds.edge_kind_can_generic_all: AccessMaskFlags.GENERIC_ALL,
        kinds.edge_kind_can_generic_execute: AccessMaskFlags.GENERIC_EXECUTE,
        kinds.edge_kind_can_generic_write: AccessMaskFlags.GENERIC_WRITE,
        kinds.edge_kind_can_generic_read: AccessMaskFlags.GENERIC_READ,
    }

    # ACE type constants
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01

    share_rights = {}
    used_fallback = False

    try:
        logger.debug(
            f"[collect_share_rights] Retrieving security descriptor for share: {share_name}"
        )
        sd = smb_session.get_share_security_descriptor(share_name)

        if sd is None or len(sd) == 0:
            # Try fallback: get the root folder's security descriptor
            logger.debug(
                f"[collect_share_rights] Share-level security descriptor unavailable for '{share_name}', trying root folder fallback..."
            )
            sd = smb_session.get_share_root_security_descriptor(share_name)
            if sd is not None and len(sd) > 0:
                used_fallback = True
                logger.debug(
                    f"[collect_share_rights] Using root folder NTFS permissions as fallback for share: {share_name}"
                )
            else:
                logger.warning(
                    f"[collect_share_rights] Could not retrieve security descriptor for share: {share_name} (both share-level and root folder fallback failed). No share rights edges will be created. This may be due to insufficient privileges or the remote registry service being disabled."
                )
                return share_rights

        logger.debug(
            f"[collect_share_rights] Security descriptor retrieved ({len(sd)} bytes) for share: {share_name}{' (via root folder fallback)' if used_fallback else ''}"
        )

        # Parse the security descriptor
        security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR()
        security_descriptor.fromString(sd)

        # Check if DACL exists
        if security_descriptor["Dacl"] is None:
            logger.debug(f"[collect_share_rights] DACL is None for share: {share_name}")
            return share_rights

        dacl_data = security_descriptor["Dacl"]["Data"]
        if dacl_data is None or len(dacl_data) == 0:
            logger.debug(
                f"[collect_share_rights] DACL is empty (no ACEs) for share: {share_name}"
            )
            return share_rights

        logger.debug(
            f"[collect_share_rights] DACL contains {len(dacl_data)} ACE(s) for share: {share_name}"
        )

        # Process each ACE in the DACL
        for ace_index, ace in enumerate(dacl_data):
            # Check if ACE has a valid SID
            if "Ace" not in ace.fields or "Sid" not in ace["Ace"].fields:
                logger.debug(
                    f"[collect_share_rights] ACE #{ace_index}: Invalid ACE structure, skipping"
                )
                continue

            if len(ace["Ace"]["Sid"]) == 0:
                logger.debug(
                    f"[collect_share_rights] ACE #{ace_index}: Empty SID, skipping"
                )
                continue

            aceType = ace["AceType"]
            aceMask = ace["Ace"]["Mask"]
            maskValue = aceMask.fields["Mask"]
            aceSid = ace["Ace"]["Sid"]
            sid = aceSid.formatCanonical()

            # Log ACE type
            ace_type_name = (
                "ACCESS_ALLOWED"
                if aceType == ACCESS_ALLOWED_ACE_TYPE
                else (
                    "ACCESS_DENIED"
                    if aceType == ACCESS_DENIED_ACE_TYPE
                    else f"UNKNOWN({aceType})"
                )
            )
            logger.debug(
                f"[collect_share_rights] ACE #{ace_index}: Type={ace_type_name}, SID={sid}, Mask=0x{maskValue:08X}"
            )

            # Only process ACCESS_ALLOWED ACEs
            if aceType != ACCESS_ALLOWED_ACE_TYPE:
                logger.debug(
                    f"[collect_share_rights] ACE #{ace_index}: Skipping non-ACCESS_ALLOWED ACE (type={aceType})"
                )
                continue

            # Check for specific rights and create edges
            access_flags = [flag for flag in AccessMaskFlags if flag.value & maskValue]

            if len(access_flags) == 0:
                logger.debug(
                    f"[collect_share_rights] ACE #{ace_index}: No matching access flags for mask 0x{maskValue:08X}"
                )
                continue

            logger.debug(
                f"[collect_share_rights] ACE #{ace_index}: Matched flags: {[flag.name for flag in access_flags]}"
            )

            # Map access flags to edge kinds
            edges_added = []
            for edgeName, edgeValue in map_rights.items():
                if edgeValue in access_flags:
                    if sid not in share_rights:
                        share_rights[sid] = []
                    share_rights[sid].append(edgeName)
                    edges_added.append(edgeName)

            if edges_added:
                logger.debug(
                    f"[collect_share_rights] ACE #{ace_index}: Created {len(edges_added)} edge(s) for SID {sid}: {edges_added}"
                )

        # Summary
        total_edges = sum(len(edges) for edges in share_rights.values())
        logger.debug(
            f"[collect_share_rights] Summary for share '{share_name}': {len(share_rights)} SID(s), {total_edges} total edge(s)"
        )

    except Exception as err:
        logger.debug(
            f"[collect_share_rights] Error processing share rights for {share_name}: {err}"
        )
        raise err

    return share_rights
