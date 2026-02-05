#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_contents_in_share.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

from threading import Lock, Event
from typing import Optional

from shareql.evaluate.evaluator import RulesEvaluator

from sharehound.collector.collect_contents_at_depth import \
    collect_contents_at_depth
from sharehound.collector.opengraph_context import OpenGraphContext
from sharehound.core.Logger import TaskLogger
from sharehound.core.SMBSession import SMBSession


def collect_contents_in_share(
    smb_session: SMBSession,
    ogc: OpenGraphContext,
    rules_evaluator: RulesEvaluator,
    worker_results: dict,
    results_lock: Lock,
    logger: TaskLogger,
    timeout_event: Optional[Event] = None,
):
    """
    Entry point function to collect contents in an SMB share using BFS traversal.

    This function initiates a breadth-first search traversal of the file share,
    starting from the root directory and exploring directories level by level
    up to the specified maximum depth.

    Args:
        smb_session: The SMB session object for connecting to the share
        ogc: The opengraph context object
        rules_evaluator: The rules evaluator object
        worker_results: The worker results object
        results_lock: The results lock object
        logger: TaskLogger object for logging operations
        maxdepth (int): Maximum depth to traverse (default: 5)

    Returns:
        tuple: (total_file_count, skipped_files_count, processed_files_count, total_directory_count, skipped_directories_count, processed_directories_count) - Number of contents found
    """

    logger.debug(
        f"Collecting contents in share {ogc.get_share().id} using BFS traversal..."
    )

    # Start BFS traversal from root
    (
        total_file_count,
        skipped_files_count,
        processed_files_count,
        total_directory_count,
        skipped_directories_count,
        processed_directories_count,
    ) = collect_contents_at_depth(
        smb_session=smb_session,
        ogc=ogc,
        rules_evaluator=rules_evaluator,
        worker_results=worker_results,
        results_lock=results_lock,
        logger=logger,
        depth=0,
        timeout_event=timeout_event,
    )

    return (
        total_file_count,
        skipped_files_count,
        processed_files_count,
        total_directory_count,
        skipped_directories_count,
        processed_directories_count,
    )
