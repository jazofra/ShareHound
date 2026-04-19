#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_contents_at_depth.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import ntpath
import os
from threading import Event, Lock
from typing import Optional

from bhopengraph.Node import Node
from bhopengraph.Properties import Properties
from shareql.evaluate.evaluator import RulesEvaluator
from shareql.objects.directory import RuleObjectDirectory
from shareql.objects.file import RuleObjectFile

import sharehound.kinds as kinds
from sharehound.collector.collect_ntfs_rights import collect_ntfs_rights
from sharehound.collector.opengraph_context import OpenGraphContext
from sharehound.core.Logger import TaskLogger
from sharehound.core.SMBSession import SMBSession


def get_extension_from_filename(filename: str) -> str:
    """
    Get the extension from a filename.

    Args:
        filename: The filename to get the extension from

    Returns:
        The extension of the filename
    """
    extension = os.path.splitext(filename)[1]
    if not extension:
        return ""
    return extension.lower()


def collect_contents_at_depth(
    smb_session: SMBSession,
    ogc: OpenGraphContext,
    rules_evaluator: RulesEvaluator,
    worker_results: dict,
    results_lock: Lock,
    logger: TaskLogger,
    depth: int = 0,
    timeout_event: Optional[Event] = None,
):
    """
    Recursive function to perform BFS traversal of file share directories.

    This function implements a breadth-first search algorithm to traverse
    directories in the file share. It processes all items at the current
    depth before moving to the next level, ensuring proper depth control.

    Args:
        smb_session: The SMB session object for connecting to the share
        path (str): Current directory path being processed
        ogc: The opengraph context object
        rules_evaluator: The rules evaluator object
        worker_results: The worker results object
        results_lock: The results lock object
        logger: TaskLogger object for logging operations
        maxdepth (int): Maximum depth to traverse
        depth (int): Current depth level

    Returns:
        tuple: (total_file_count, skipped_files_count, processed_files_count, total_directory_count, skipped_directories_count, processed_directories_count) - Cumulative counts of files and directories found
    """

    total_file_count = 0
    skipped_files_count = 0
    processed_files_count = 0
    total_directory_count = 0
    skipped_directories_count = 0
    processed_directories_count = 0

    # Check if timeout has been reached
    if timeout_event is not None and timeout_event.is_set():
        logger.debug("Timeout reached, stopping directory traversal")
        return (
            total_file_count,
            skipped_files_count,
            processed_files_count,
            total_directory_count,
            skipped_directories_count,
            processed_directories_count,
        )

    # Set the current share
    shareDisplayName = ogc.get_share().properties.get_property("displayName")
    smb_session.set_share(shareDisplayName)
    rules_evaluator.context.set_depth(depth)

    logger.increment_indent()

    # Get contents of current directory
    try:
        contents = smb_session.list_contents(ogc.get_string_path_from_root())
    except Exception as e:
        logger.debug(
            f"Error listing contents of path '{ogc.get_string_path_from_root()}': {e}"
        )
        logger.decrement_indent()
        return (
            total_file_count,
            skipped_files_count,
            processed_files_count,
            total_directory_count,
            skipped_directories_count,
            processed_directories_count,
        )

    # Process current level items
    directories_to_explore_next = []

    for content_name, content in contents.items():
        # Skip . and .. entries
        if content_name in [".", ".."]:
            continue

        # Create full path for the current item
        full_path = ntpath.join(ogc.get_string_path_from_root(), content_name)

        # Create UNC path
        unc_path = f"\\\\{smb_session.getRemoteName()}\\{shareDisplayName}\\{full_path}"

        element_rights = collect_ntfs_rights(
            smb_session=smb_session,
            ogc=ogc,
            rules_evaluator=rules_evaluator,
            content=content,
            logger=logger,
        )
        ogc.set_element_rights(element_rights)

        if content.is_directory():
            # This is a directory

            # Evaluate the rules and see if we can process this directory
            # If we are not allowed to process this directory, skip it
            ruleObjectDirectory = RuleObjectDirectory(
                name=content.get_longname(),
                path=full_path,
                modified_at=getattr(content, "get_mtime", lambda: None)(),
                created_at=getattr(content, "get_ctime", lambda: None)(),
            )

            if not rules_evaluator.can_explore(ruleObjectDirectory):
                skipped_directories_count += 1
                continue

            total_directory_count += 1

            # Track pending directory when it will be processed
            with results_lock:
                worker_results["directories_pending"] += 1

            # Create Directory node
            directoryNode = Node(
                kinds=[kinds.node_kind_content_directory],
                id=f"DIR:{unc_path}",
                properties=Properties(
                    name=content_name,
                    Path=full_path,
                    UNCPath=unc_path,
                    createdAt=getattr(content, "get_ctime", lambda: None)(),
                    modifiedAt=getattr(content, "get_mtime", lambda: None)(),
                ),
            )
            ogc.set_element(directoryNode)

            if rules_evaluator.can_process(ruleObjectDirectory):
                processed_directories_count += 1

            # Add directory to the list for next level exploration
            directories_to_explore_next.append((directoryNode, element_rights))

        else:
            # This is a file

            # Evaluate the rules and see if we can process this file
            # If we are not allowed to process this file, skip it
            ruleObjectFile = RuleObjectFile(
                name=content_name,
                path=full_path,
                size=getattr(content, "get_filesize", lambda: 0)(),
                modified_at=getattr(content, "get_mtime", lambda: None)(),
                created_at=getattr(content, "get_ctime", lambda: None)(),
            )

            if not rules_evaluator.can_process(ruleObjectFile):
                skipped_files_count += 1
                continue

            total_file_count += 1

            # Track pending file when it will be processed
            with results_lock:
                worker_results["files_pending"] += 1

            logger.debug(f"📄 {content_name}")

            # Create File node
            file_node = Node(
                kinds=[kinds.node_kind_content_file],
                id=f"FILE:{unc_path}",
                properties=Properties(
                    name=content_name,
                    Path=full_path,
                    UNCPath=unc_path,
                    fileSize=getattr(content, "get_filesize", lambda: 0)(),
                    createdAt=getattr(content, "get_ctime", lambda: None)(),
                    modifiedAt=getattr(content, "get_mtime", lambda: None)(),
                    extension=get_extension_from_filename(content_name),
                ),
            )
            ogc.set_element(file_node)

            can_process = rules_evaluator.can_process(ruleObjectFile)
            if can_process:
                ogc.add_path_to_graph()
                processed_files_count += 1
                # File processed → decrement pending exactly once
                with results_lock:
                    worker_results["files_pending"] -= 1

        ogc.clear_element()

    # Process next level directories (BFS approach)
    for directoryNode, element_rights in directories_to_explore_next:
        # Check timeout before processing each directory
        if timeout_event is not None and timeout_event.is_set():
            logger.debug("Timeout reached, skipping remaining directories")
            break

        logger.debug(f"📁 {directoryNode.properties['name']}")

        ogc.push_path(directoryNode, element_rights)

        (
            sub_total_file_count,
            sub_skipped_files_count,
            sub_processed_files_count,
            sub_total_directory_count,
            sub_skipped_directories_count,
            sub_processed_directories_count,
        ) = collect_contents_at_depth(
            smb_session=smb_session,
            ogc=ogc,
            rules_evaluator=rules_evaluator,
            worker_results=worker_results,
            results_lock=results_lock,
            logger=logger,
            depth=(depth + 1),
            timeout_event=timeout_event,
        )
        with results_lock:
            # Files counters
            worker_results["files_total"] += sub_total_file_count
            total_file_count += sub_total_file_count

            worker_results["files_skipped"] += sub_skipped_files_count
            skipped_files_count += sub_skipped_files_count

            worker_results["files_processed"] += sub_processed_files_count
            processed_files_count += sub_processed_files_count

            # Directories counters
            worker_results["directories_total"] += sub_total_directory_count
            total_directory_count += sub_total_directory_count

            worker_results["directories_skipped"] += sub_skipped_directories_count
            skipped_directories_count += sub_skipped_directories_count

            worker_results["directories_processed"] += sub_processed_directories_count
            processed_directories_count += sub_processed_directories_count

            # Current directory completed → decrement pending exactly once
            worker_results["directories_pending"] -= 1

        ogc.pop_path()

    # Decrement logger indent when leaving this depth level
    logger.decrement_indent()

    return (
        total_file_count,
        skipped_files_count,
        processed_files_count,
        total_directory_count,
        skipped_directories_count,
        processed_directories_count,
    )
