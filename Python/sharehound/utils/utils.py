#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 18 aug 2025

from __future__ import annotations

import fnmatch
import ntpath
import re
import socket
from typing import TYPE_CHECKING

import dns.exception
import dns.resolver
from impacket.smbconnection import SessionError

if TYPE_CHECKING:
    from typing import Optional


def parse_lm_nt_hashes(lm_nt_hashes_string: str) -> tuple[str, str]:
    """
    Parse the input string containing LM and NT hash values and return them separately.

    This function takes a string containing LM and NT hash values, typically separated by a colon (:).
    It returns the LM and NT hash values as separate strings. If only one hash value is provided, it is
    assumed to be the NT hash and the LM hash is set to its default value. If no valid hash values are
    found, both return values are empty strings.

    Args:
        lm_nt_hashes_string (str): A string containing LM and NT hash values separated by a colon.

    Returns:
        tuple: A tuple containing two strings (lm_hash_value, nt_hash_value).
               - lm_hash_value: The LM hash value or its default if not provided.
               - nt_hash_value: The NT hash value or its default if not provided.

    Extracted from p0dalirius/sectools library
    Src: https://github.com/p0dalirius/sectools/blob/7bb3f5cb7815ad4d4845713c8739e2e2b0ea4e75/sectools/windows/crypto.py#L11-L24
    """

    lm_hash_value, nt_hash_value = "", ""
    if lm_nt_hashes_string is not None:
        matched = re.match(
            "([0-9a-f]{32})?(:)?([0-9a-f]{32})?", lm_nt_hashes_string.strip().lower()
        )
        m_lm_hash, m_sep, m_nt_hash = matched.groups()
        if m_lm_hash is None and m_sep is None and m_nt_hash is None:
            lm_hash_value, nt_hash_value = "", ""
        elif m_lm_hash is None and m_nt_hash is not None:
            lm_hash_value = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash_value = m_nt_hash
        elif m_lm_hash is not None and m_nt_hash is None:
            lm_hash_value = m_lm_hash
            nt_hash_value = "31d6cfe0d16ae931b73c59d7e0c089c0"
    return lm_hash_value, nt_hash_value


def filesize(size: int) -> str:
    """
    Convert a file size from bytes to a more readable format using the largest appropriate unit.

    This function takes an integer representing a file size in bytes and converts it to a human-readable
    string using the largest appropriate unit from bytes (B) to petabytes (PB). The result is rounded to
    two decimal places.

    Args:
        l (int): The file size in bytes.

    Returns:
        str: A string representing the file size in a more readable format, including the appropriate unit.
    """

    units = ["B", "kB", "MB", "GB", "TB", "PB"]
    for k in range(len(units)):
        if size < (1024 ** (k + 1)):
            break
    return "%4.2f %s" % (round(size / (1024 ** (k)), 2), units[k])


def STYPE_MASK(stype_value: int) -> list[str]:
    """
    Extracts the share type flags from a given share type value.

    This function uses bitwise operations to determine which share type flags are set in the provided `stype_value`.
    It checks against known share type flags and returns a list of the flags that are set.

    Parameters:
        stype_value (int): The share type value to analyze, typically obtained from SMB share properties.

    Returns:
        list: A list of strings, where each string represents a share type flag that is set in the input value.
    """

    known_flags = {
        # One of the following values may be specified. You can isolate these values by using the STYPE_MASK value.
        # Disk drive.
        "STYPE_DISKTREE": 0x0,
        # Print queue.
        "STYPE_PRINTQ": 0x1,
        # Communication device.
        "STYPE_DEVICE": 0x2,
        # Interprocess communication (IPC).
        "STYPE_IPC": 0x3,
        # In addition, one or both of the following values may be specified.
        # Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$).
        # Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see Network Share Functions.
        "STYPE_SPECIAL": 0x80000000,
        # A temporary share.
        "STYPE_TEMPORARY": 0x40000000,
    }
    flags: list[str] = []
    if (stype_value & 0b11) == known_flags["STYPE_DISKTREE"]:
        flags.append("STYPE_DISKTREE")
    elif (stype_value & 0b11) == known_flags["STYPE_PRINTQ"]:
        flags.append("STYPE_PRINTQ")
    elif (stype_value & 0b11) == known_flags["STYPE_DEVICE"]:
        flags.append("STYPE_DEVICE")
    elif (stype_value & 0b11) == known_flags["STYPE_IPC"]:
        flags.append("STYPE_IPC")
    if (stype_value & known_flags["STYPE_SPECIAL"]) == known_flags["STYPE_SPECIAL"]:
        flags.append("STYPE_SPECIAL")
    if (stype_value & known_flags["STYPE_TEMPORARY"]) == known_flags["STYPE_TEMPORARY"]:
        flags.append("STYPE_TEMPORARY")
    return flags


def is_port_open(target: str, port: int, timeout: float) -> tuple[bool, Optional[str]]:
    """
    Check if a specific port on a target host is open.

    This function attempts to establish a TCP connection to the specified port on the target host.
    If the connection is successful, it indicates that the port is open. If the connection fails,
    it returns the error message.

    Args:
        target (str): The hostname or IP address of the target host.
        port (int): The port number to check.
        timeout (float): The timeout in seconds for the connection attempt. Default is 1.0 second.

    Returns:
        bool, str: True if the port is open, otherwise False and error message.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            return True, None
    except Exception as e:
        return False, str(e)


def dns_resolve(options, target_name):
    """
    Resolve a domain name to an IP address using DNS.

    This function uses the `dns.resolver` module to resolve a domain name to an IP address.
    It supports both UDP and TCP DNS queries, and can use a custom nameserver if provided.

    Args:
        options: Configuration options containing the nameserver to use.
        target_name (str): The domain name to resolve.

    Returns:
        str: The IP address of the domain name, or None if the domain name does not exist.
    """

    dns_resolver = dns.resolver.Resolver()
    if options.nameserver is not None:
        dns_resolver.nameservers = [options.nameserver]
    else:
        dns_resolver.nameservers = [options.auth_dc_ip]
    dns_answer = None

    # Try UDP
    try:
        dns_answer = dns_resolver.resolve(target_name, rdtype="A", tcp=False)
    except dns.resolver.NXDOMAIN:
        # the domain does not exist so dns resolutions remain empty
        pass
    except dns.resolver.NoAnswer:
        # domains existing but not having AAAA records is common
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.exception.DNSException:
        pass

    if dns_answer is None:
        # Try TCP
        try:
            dns_answer = dns_resolver.resolve(target_name, rdtype="A", tcp=True)
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer:
            # domains existing but not having AAAA records is common
            pass
        except dns.resolver.NoNameservers:
            pass
        except dns.exception.DNSException:
            pass

    target_ip = []
    if dns_answer is not None:
        target_ip = [ip.address for ip in dns_answer]

    if len(target_ip) != 0:
        return target_ip[0]
    else:
        return None


def smb_entry_iterator(
    smb_client,
    smb_share: str,
    start_paths: list[str],
    exclusion_rules=[],
    max_depth: Optional[int] = None,
    min_depth: int = 0,
    current_depth: int = 0,
    filters: Optional[dict] = None,
):
    """
    Iterates over SMB entries by traversing directories in a depth-first manner.

    This function recursively traverses through directories on an SMB share, yielding
    each entry found along with its full path, current depth, and information on whether
    it is the last entry in its directory.

    Args:
        smb_client: The SMB client instance used to interact with the remote share.
        smb_share (str): The name of the SMB share being traversed.
        start_paths (list): A list of initial paths to start traversing from.
        exclusion_rules (list): Rules to exclude certain directories from traversal.
        max_depth (int, optional): The maximum depth to traverse. If None, no depth limit is applied.
        current_depth (int): The current depth of traversal in the directory hierarchy.

    Yields:
        tuple: A tuple containing:
            - entry: The current SMB entry object (e.g., file or directory).
            - fullpath (str): The full path to the current entry.
            - depth (int): The current depth level of the entry within the traversal.
            - is_last_entry (bool): True if the entry is the last within its directory, False otherwise.
    """

    def entry_matches_filters(entry, filters) -> bool:
        """
        Checks if an entry matches the provided filters.

        Args:
            entry: The SMB entry to check.
            filters (dict): Dictionary of filters.

        Returns:
            bool: True if the entry matches the filters, False otherwise.
        """

        if filters is None:
            return True

        # Filter by type
        entry_type = "d" if entry.is_directory() else "f"
        if "type" in filters and filters["type"] != entry_type:
            return False

        # Filter by name (case-sensitive)
        if "name" in filters:
            name_patterns = filters["name"]
            if isinstance(name_patterns, str):
                name_patterns = [name_patterns]
            if not any(
                fnmatch.fnmatchcase(entry.get_longname(), pattern)
                for pattern in name_patterns
            ):
                return False

        # Filter by name (case-insensitive)
        if "iname" in filters:
            iname_patterns = filters["iname"]
            if isinstance(iname_patterns, str):
                iname_patterns = [iname_patterns]
            if not any(
                fnmatch.fnmatch(entry.get_longname().lower(), pattern.lower())
                for pattern in iname_patterns
            ):
                return False

        # Filter by size
        if "size" in filters and not entry.is_directory():
            size_filter = filters["size"]
            size = entry.get_filesize()
            if not size_matches_filter(size, size_filter):
                return False

        return True

    def size_matches_filter(size: int, size_filter: str) -> bool:
        """
        Checks if a size matches the size filter.

        Args:
            size (int): The size in bytes.
            size_filter (str): The size filter string (e.g., '+1M', '-500K').

        Returns:
            bool: True if the size matches the filter, False otherwise.
        """
        import re

        match = re.match(r"([+-]?)(\d+)([BKMGTP]?)", size_filter, re.IGNORECASE)
        if not match:
            return False

        operator, number, unit = match.groups()
        number = int(number)
        unit_multipliers = {
            "": 1,
            "B": 1,
            "K": 1024,
            "M": 1024**2,
            "G": 1024**3,
            "T": 1024**4,
            "P": 1024**5,
        }
        multiplier = unit_multipliers.get(unit.upper(), 1)
        threshold = number * multiplier

        if operator == "+":
            return size >= threshold
        elif operator == "-":
            return size <= threshold
        else:
            return size == threshold

    # Entrypoint
    for base_path in start_paths:
        try:
            entries = smb_client.listPath(
                shareName=smb_share, path=ntpath.join(base_path, "*")
            )

            entries = [e for e in entries if e.get_longname() not in [".", ".."]]
            entries.sort(key=lambda e: (not e.is_directory(), e.get_longname().lower()))

            entries_count = len(entries)
            for index, entry in enumerate(entries):
                # Determine if this is the last entry in the directory
                is_last_entry = index == entries_count - 1
                entry_name = entry.get_longname()
                fullpath = ntpath.join(base_path, entry_name)

                # Apply exclusion rules
                exclude = False
                for rule in exclusion_rules:
                    dirname = rule["dirname"]
                    depth = rule.get("depth", -1)
                    case_sensitive = rule.get("case_sensitive", True)
                    match_name = entry_name if case_sensitive else entry_name.lower()
                    match_dirname = dirname if case_sensitive else dirname.lower()

                    if match_name == match_dirname and (
                        depth == -1 or current_depth <= depth
                    ):
                        exclude = True
                        break

                if exclude:
                    continue

                # Apply depth filtering
                if (
                    max_depth is not None and current_depth > max_depth
                ) or current_depth < min_depth:
                    continue

                # Recursion for directories
                if entry.is_directory():
                    # Yield the directory if it matches the criteria
                    if entry_matches_filters(entry, filters):
                        yield entry, fullpath, current_depth, is_last_entry

                    if max_depth is None or current_depth < max_depth:
                        yield from smb_entry_iterator(
                            smb_client=smb_client,
                            smb_share=smb_share,
                            start_paths=[fullpath],
                            exclusion_rules=exclusion_rules,
                            max_depth=max_depth,
                            min_depth=min_depth,
                            current_depth=current_depth + 1,
                            filters=filters,
                        )
                else:
                    if entry_matches_filters(entry, filters):
                        yield entry, fullpath, current_depth, is_last_entry

        except SessionError as err:
            message = f"{err}. Base path: {base_path}"
            print("[\x1b[1;91merror\x1b[0m] %s" % message)
            continue
