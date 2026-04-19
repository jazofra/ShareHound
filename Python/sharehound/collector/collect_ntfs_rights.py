#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_ntfs_rights.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

from typing import Union

from impacket.ldap import ldaptypes
from impacket.smb import SharedFile
from shareql.evaluate.evaluator import RulesEvaluator

import sharehound.kinds as kinds
from sharehound.collector.opengraph_context import OpenGraphContext
from sharehound.core.Logger import Logger, TaskLogger
from sharehound.core.SMBSession import SMBSession


def collect_ntfs_rights(
    smb_session: SMBSession,
    ogc: OpenGraphContext,
    rules_evaluator: RulesEvaluator,
    content: SharedFile,
    logger: Union[Logger, TaskLogger],
):
    """
    Process NTFS rights for a file or directory and create corresponding edges.

    This function retrieves the security descriptor for a file or directory,
    processes the DACL to extract access rights, and creates edges between
    principals (SIDs) and the file/directory with the appropriate NTFS rights.

    Args:
        smb_session: The SMB session object for connecting to the share
        graph: The graph object to add nodes and edges to
        rules_evaluator: The rules evaluator object
        node: The file or directory node to process rights for
        path: The path of the file or directory
        content: The SharedFile object representing the file/directory
        logger: Logger object for logging operations
    """

    try:
        ntfsrights_edges = {}

        # Get the security descriptor for the file/directory
        path = ogc.get_string_path_from_root()

        security_descriptor = None
        security_descriptor = smb_session.get_entry_security_descriptor(path, content)

        if security_descriptor is None:
            return

        # Process each ACE in the DACL
        if (
            security_descriptor["Dacl"] is not None
            and len(security_descriptor["Dacl"]["Data"]) > 0
        ):
            for acl in security_descriptor["Dacl"]["Data"]:
                if len(acl["Ace"]["Sid"]) == 0:
                    continue

                sid = acl["Ace"]["Sid"].formatCanonical()

                # Check for specific rights and create edges
                mask = acl["Ace"]["Mask"]

                map_rights = {
                    kinds.edge_kind_can_ntfs_generic_read: ldaptypes.ACCESS_MASK.GENERIC_READ,
                    kinds.edge_kind_can_ntfs_generic_write: ldaptypes.ACCESS_MASK.GENERIC_WRITE,
                    kinds.edge_kind_can_ntfs_generic_execute: ldaptypes.ACCESS_MASK.GENERIC_EXECUTE,
                    kinds.edge_kind_can_ntfs_generic_all: ldaptypes.ACCESS_MASK.GENERIC_ALL,
                    kinds.edge_kind_can_ntfs_maximum_allowed: ldaptypes.ACCESS_MASK.MAXIMUM_ALLOWED,
                    kinds.edge_kind_can_ntfs_access_system_security: ldaptypes.ACCESS_MASK.ACCESS_SYSTEM_SECURITY,
                    kinds.edge_kind_can_ntfs_synchronize: ldaptypes.ACCESS_MASK.SYNCHRONIZE,
                    kinds.edge_kind_can_ntfs_write_owner: ldaptypes.ACCESS_MASK.WRITE_OWNER,
                    kinds.edge_kind_can_ntfs_write_dacl: ldaptypes.ACCESS_MASK.WRITE_DACL,
                    kinds.edge_kind_can_ntfs_read_control: ldaptypes.ACCESS_MASK.READ_CONTROL,
                    kinds.edge_kind_can_ntfs_delete: ldaptypes.ACCESS_MASK.DELETE,
                }
                for right, maskValue in map_rights.items():
                    if mask.hasPriv(maskValue):
                        if sid not in ntfsrights_edges:
                            ntfsrights_edges[sid] = []
                        ntfsrights_edges[sid].append(right)

    except Exception as err:
        logger.debug(f"Error processing NTFS rights for '{path}': {err}")
        raise err

    return ntfsrights_edges
