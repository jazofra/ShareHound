#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : sid_utils.py
# Date created       : 26 Feb 2026


def is_domain_sid(sid: str) -> bool:
    """Check if a SID is a domain-relative SID (S-1-5-21-*)."""
    return sid.startswith("S-1-5-21-")


def normalize_sid(sid: str, domain_fqdn: str) -> str:
    """
    Normalize a SID for BloodHound graph matching.

    Domain SIDs (S-1-5-21-*) are returned as-is since they already contain
    the domain identifier.

    All other SIDs (well-known like S-1-1-0, BUILTIN groups like S-1-5-32-*,
    etc.) are prefixed with the Active Directory domain FQDN:
        e.g., DOMAIN.COM-S-1-1-0
        e.g., DOMAIN.COM-S-1-5-32-545

    Args:
        sid: The raw SID string (e.g., S-1-1-0, S-1-5-32-545, S-1-5-21-...)
        domain_fqdn: The Active Directory domain FQDN (e.g., THIS.DOMAIN.COM)

    Returns:
        The normalized SID string with the appropriate prefix.
    """
    if is_domain_sid(sid):
        return sid

    if domain_fqdn:
        return f"{domain_fqdn}-{sid}".upper()

    return sid
