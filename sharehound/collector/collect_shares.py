#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_shares.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

from threading import Lock
from typing import Union

from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Properties import Properties
from shareql.evaluate.evaluator import RulesEvaluator
from shareql.objects.share import RuleObjectShare

import sharehound.kinds as kinds
from sharehound.collector.collect_contents_in_share import \
    collect_contents_in_share
from sharehound.collector.collect_share_rights import collect_share_rights
from sharehound.collector.opengraph_context import OpenGraphContext
from sharehound.core.Logger import Logger, TaskLogger
from sharehound.core.SMBSession import SMBSession


def collect_shares(
    smb_session: SMBSession,
    graph: OpenGraph,
    logger: Union[Logger, TaskLogger],
    rules_evaluator: RulesEvaluator,
    worker_results: dict,
    results_lock: Lock,
) -> tuple[int, int, int, int, int, int, int, int]:
    """
    Collects information about SMB shares and their contents.

    Args:
        smb_session: The SMB session object for connecting to the share
        graph: The graph object to add nodes and edges to
        logger: Logger object for logging operations
        rules_evaluator: The rules evaluator object
        worker_results: The worker results object
        results_lock: The results lock object
    Returns:
        tuple: (total_share_count, skipped_shares_count, total_file_count, skipped_files_count, processed_files_count, total_directory_count, skipped_directories_count, processed_directories_count) - Total counts of shares, files and directories found across all shares
    """

    ogc = OpenGraphContext(graph=graph, logger=logger)

    host_remote_name = smb_session.getRemoteName()
    logger.debug(f"Collecting shares on {host_remote_name} ...")

    # Prepare host node
    host = Node(
        kinds=[kinds.node_kind_network_share_host],
        id=host_remote_name,
        properties=Properties(
            name=host_remote_name,
        ),
    )
    ogc.set_host(host)

    total_file_count = 0
    total_directory_count = 0
    total_share_count = 0
    skipped_shares_count = 0
    skipped_files_count = 0
    processed_files_count = 0
    skipped_directories_count = 0
    processed_directories_count = 0

    shares = smb_session.list_shares()
    for share_name, share_data in shares.items():
        total_share_count += 1

        # Evaluate the rules against the share
        rule_object_share = RuleObjectShare(
            name=share_name,
            description=share_data.get("description", ""),
            hidden=share_name.endswith("$"),
        )
        rules_evaluator.context.set_share(rule_object_share)
        if not rules_evaluator.can_explore(rule_object_share):
            logger.debug(f"[>] Skipping share: {share_name}")
            skipped_shares_count += 1
            continue

        # Create share OpenGraph node
        share_node = Node(
            kinds=[kinds.node_kind_network_share_smb],
            id=f"\\\\{host_remote_name}\\{share_name}\\",
            properties=Properties(
                displayName=share_name,
                description=share_data.get("description", ""),
                hidden=share_name.endswith("$"),
            ),
        )
        ogc.set_share(share_node)

        # Collect share security descriptor
        share_rights = collect_share_rights(
            smb_session=smb_session,
            share_name=share_name,
            rules_evaluator=rules_evaluator,
            logger=logger,
        )
        ogc.set_share_rights(share_rights)

        can_process = rules_evaluator.can_process(rule_object_share)
        logger.debug(f"[collect_shares] can_process({share_name}) = {can_process}")
        if can_process:
            ogc.add_path_to_graph()
            logger.debug(f"[collect_shares] Total edges created so far for share '{share_name}': {ogc.get_total_edges_created()}")
        else:
            logger.debug(f"[collect_shares] Skipping add_path_to_graph for share '{share_name}' because can_process returned False")

        # Collect contents of the share
        (
            sub_total_file_count,
            sub_skipped_files_count,
            sub_processed_files_count,
            sub_total_directory_count,
            sub_skipped_directories_count,
            sub_processed_directories_count,
        ) = collect_contents_in_share(
            smb_session=smb_session,
            ogc=ogc,
            rules_evaluator=rules_evaluator,
            worker_results=worker_results,
            results_lock=results_lock,
            logger=logger,
        )

        # Add to totals
        total_file_count += sub_total_file_count
        total_directory_count += sub_total_directory_count
        skipped_files_count += sub_skipped_files_count
        processed_files_count += sub_processed_files_count
        skipped_directories_count += sub_skipped_directories_count
        processed_directories_count += sub_processed_directories_count

    return (
        total_share_count,
        skipped_shares_count,
        total_file_count,
        skipped_files_count,
        processed_files_count,
        total_directory_count,
        skipped_directories_count,
        processed_directories_count,
    )
