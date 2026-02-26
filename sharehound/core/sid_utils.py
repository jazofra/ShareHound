#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sid_utils.py
# Date created       : 26 Feb 2026


def is_domain_sid(sid: str) -> bool:
    """Check if a SID is a domain-relative SID (S-1-5-21-*)."""
    return sid.startswith("S-1-5-21-")


def is_builtin_sid(sid: str) -> bool:
    """Check if a SID is a BUILTIN group SID (S-1-5-32-*)."""
    return sid.startswith("S-1-5-32-")


def _ensure_fqdn(computer_name: str, domain_fqdn: str) -> str:
    """Ensure a computer name is a fully-qualified domain name."""
    if not computer_name:
        return ""
    # If computer_name already contains a dot, assume it's an FQDN
    if "." in computer_name:
        return computer_name.upper()
    # Otherwise, append the domain to form a FQDN
    if domain_fqdn:
        return f"{computer_name}.{domain_fqdn}".upper()
    return computer_name.upper()


def normalize_sid(sid: str, domain_fqdn: str, computer_name: str) -> str:
    """
    Normalize a SID for BloodHound graph matching.

    Domain SIDs (S-1-5-21-*) are returned as-is since they already contain
    the domain identifier.

    BUILTIN group SIDs (S-1-5-32-*) are prefixed with the computer FQDN
    since these groups are local to each computer:
        e.g., COMPUTER.DOMAIN.COM-S-1-5-32-545

    Other well-known SIDs (e.g., S-1-1-0 Everyone) are prefixed with the
    Active Directory domain FQDN:
        e.g., DOMAIN.COM-S-1-1-0

    Args:
        sid: The raw SID string (e.g., S-1-1-0, S-1-5-32-545, S-1-5-21-...)
        domain_fqdn: The Active Directory domain FQDN (e.g., THIS.DOMAIN.COM)
        computer_name: The target computer's name or FQDN

    Returns:
        The normalized SID string with the appropriate prefix.
    """
    if is_domain_sid(sid):
        return sid

    if is_builtin_sid(sid):
        computer_fqdn = _ensure_fqdn(computer_name, domain_fqdn)
        if computer_fqdn:
            return f"{computer_fqdn}-{sid}".upper()
        return sid

    # Well-known SIDs get the AD domain prefix
    if domain_fqdn:
        return f"{domain_fqdn}-{sid}".upper()

    return sid
