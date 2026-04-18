#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import time

from rich.console import Console
from rich.progress import Progress, TextColumn
from rich.text import Text


class CustomProgressColumn(TextColumn):
    """Custom column to show processed/skipped/pending/total stats"""

    def render(self, task):
        # Get custom data from task fields if available
        processed = getattr(task, "processed", 0)
        skipped = getattr(task, "skipped", 0)
        pending = getattr(task, "pending", 0)
        total = task.total or 0

        return Text(
            f"processed:{processed} | skipped:{skipped} | pending:{pending} | total:{total}",
            style="progress.data",
        )


def status(console: Console, worker_results: dict, futures: list):
    status_verb = "[[bold bright_yellow]status[/bold bright_yellow]]"

    # Create custom progress with our column
    custom_progress = Progress(
        TextColumn("{task.description}"),
        # BarColumn(),
        # TaskProgressColumn(),
        CustomProgressColumn(""),
        auto_refresh=True,
        refresh_per_second=1,
    )

    with custom_progress as progress:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        milliseconds = f".{int(time.time() * 1000) % 1000:03d}"
        timestamp_with_ms = timestamp + milliseconds

        # Create 4 progress bars for different types of work
        # Use max(1, value) to avoid division by zero and ensure we have a reasonable total
        host_task = progress.add_task(
            f"[{timestamp_with_ms}] {status_verb} Processing hosts", total=len(futures)
        )
        share_task = progress.add_task(
            f"[{timestamp_with_ms}] {status_verb} Processing shares",
            total=max(1, worker_results["shares_total"]),
        )
        file_task = progress.add_task(
            f"[{timestamp_with_ms}] {status_verb} Processing files",
            total=max(1, worker_results["files_total"]),
        )
        dir_task = progress.add_task(
            f"[{timestamp_with_ms}] {status_verb} Processing directories",
            total=max(1, worker_results["directories_total"]),
        )

        # Initialize custom fields for each task
        progress.tasks[host_task].processed = 0
        progress.tasks[host_task].skipped = 0
        progress.tasks[host_task].pending = 0

        progress.tasks[share_task].processed = 0
        progress.tasks[share_task].skipped = 0
        progress.tasks[share_task].pending = 0

        progress.tasks[file_task].processed = 0
        progress.tasks[file_task].skipped = 0
        progress.tasks[file_task].pending = 0

        progress.tasks[dir_task].processed = 0
        progress.tasks[dir_task].skipped = 0
        progress.tasks[dir_task].pending = 0

        while len([t for t in futures if not t.done()]) > 0:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            milliseconds = f".{int(time.time() * 1000) % 1000:03d}"
            timestamp_with_ms = timestamp + milliseconds

            # Update host progress
            progress.tasks[host_task].processed = worker_results["success"]
            progress.tasks[host_task].skipped = worker_results["errors"]
            progress.tasks[host_task].pending = (
                len(futures) - worker_results["success"] - worker_results["errors"]
            )
            progress.update(
                host_task,
                completed=worker_results["success"] + worker_results["errors"],
                total=len(futures),
                description=f"[{timestamp_with_ms}] {status_verb} Processing hosts",
            )

            # Update share progress
            progress.tasks[share_task].processed = worker_results["shares_processed"]
            progress.tasks[share_task].skipped = worker_results["shares_skipped"]
            progress.tasks[share_task].pending = worker_results["shares_pending"]
            progress.update(
                share_task,
                completed=worker_results["shares_processed"]
                + worker_results["shares_skipped"],
                total=max(1, worker_results["shares_total"]),
                description=f"[{timestamp_with_ms}] {status_verb} Processing shares",
            )

            # Update file progress
            progress.tasks[file_task].processed = worker_results["files_processed"]
            progress.tasks[file_task].skipped = worker_results["files_skipped"]
            progress.tasks[file_task].pending = worker_results["files_pending"]
            progress.update(
                file_task,
                completed=worker_results["files_processed"]
                + worker_results["files_skipped"],
                total=max(1, worker_results["files_total"]),
                description=f"[{timestamp_with_ms}] {status_verb} Processing files",
            )

            # Update directory progress
            progress.tasks[dir_task].processed = worker_results["directories_processed"]
            progress.tasks[dir_task].skipped = worker_results["directories_skipped"]
            progress.tasks[dir_task].pending = worker_results["directories_pending"]
            progress.update(
                dir_task,
                completed=worker_results["directories_processed"]
                + worker_results["directories_skipped"],
                total=max(1, worker_results["directories_total"]),
                description=f"[{timestamp_with_ms}] {status_verb} Processing directories",
            )

            time.sleep(0.125)

        # Final progress update to show 100% completion
        progress.tasks[host_task].processed = worker_results["success"]
        progress.tasks[host_task].skipped = worker_results["errors"]
        progress.tasks[host_task].pending = 0
        progress.update(
            host_task,
            completed=worker_results["success"] + worker_results["errors"],
            total=len(futures),
            description=f"[{timestamp_with_ms}] {status_verb} Processing hosts",
        )

        progress.tasks[share_task].processed = worker_results["shares_processed"]
        progress.tasks[share_task].skipped = worker_results["shares_skipped"]
        progress.tasks[share_task].pending = 0
        progress.update(
            share_task,
            completed=worker_results["shares_processed"]
            + worker_results["shares_skipped"],
            total=max(1, worker_results["shares_total"]),
            description=f"[{timestamp_with_ms}] {status_verb} Processing shares",
        )

        progress.tasks[file_task].processed = worker_results["files_processed"]
        progress.tasks[file_task].skipped = worker_results["files_skipped"]
        progress.tasks[file_task].pending = 0
        progress.update(
            file_task,
            completed=worker_results["files_processed"]
            + worker_results["files_skipped"],
            total=max(1, worker_results["files_total"]),
            description=f"[{timestamp_with_ms}] {status_verb} Processing files",
        )

        progress.tasks[dir_task].processed = worker_results["directories_processed"]
        progress.tasks[dir_task].skipped = worker_results["directories_skipped"]
        progress.tasks[dir_task].pending = 0
        progress.update(
            dir_task,
            completed=worker_results["directories_processed"]
            + worker_results["directories_skipped"],
            total=max(1, worker_results["directories_total"]),
            description=f"[{timestamp_with_ms}] {status_verb} Processing directories",
        )
