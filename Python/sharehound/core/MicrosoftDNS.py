#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MicrosoftDNS.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import re

import dns.resolver
from sectools.windows.ldap import init_ldap_session


class MicrosoftDNS(object):
    """
    Class to interact with Microsoft DNS servers for resolving domain names to IP addresses.

    Attributes:
        dnsserver (str): The IP address of the DNS server.
        verbose (bool): Flag to enable verbose mode.
        auth_domain (str): The authentication domain.
        auth_username (str): The authentication username.
        auth_password (str): The authentication password.
        auth_dc_ip (str): The IP address of the domain controller.
        auth_lm_hash (str): The LM hash for authentication.
        auth_nt_hash (str): The NT hash for authentication.
    """

    __wildcard_dns_cache = {}

    def __init__(
        self,
        dnsserver,
        auth_domain,
        auth_username,
        auth_password,
        auth_dc_ip,
        auth_lm_hash,
        auth_nt_hash,
        use_ldaps=False,
        verbose=False,
    ):
        super(MicrosoftDNS, self).__init__()
        self.dnsserver = dnsserver
        self.verbose = verbose
        self.auth_domain = auth_domain
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_dc_ip = auth_dc_ip
        self.auth_lm_hash = auth_lm_hash
        self.auth_nt_hash = auth_nt_hash
        self.use_ldaps = use_ldaps

    def resolve(self, target_name):
        """
        Documentation for class MicrosoftDNS

        Attributes:
            dnsserver (str): The IP address of the DNS server.
            verbose (bool): Flag to enable verbose mode.
            auth_domain (str): The authentication domain.
            auth_username (str): The authentication username.
            auth_password (str): The authentication password.
            auth_dc_ip (str): The IP address of the domain controller.
            auth_lm_hash (str): The LM hash for authentication.
            auth_nt_hash (str): The NT hash for authentication.
        """
        target_ips = []
        for rdtype in ["A", "AAAA"]:
            dns_answer = self.get_record(value=target_name, rdtype=rdtype)
            if dns_answer is not None:
                for record in dns_answer:
                    target_ips.append(record.address)
        if self.verbose and len(target_ips) == 0:
            print("[debug] No records found for %s." % target_name)
        return target_ips

    def get_record(self, rdtype, value):
        """
        Retrieves DNS records for a specified value and record type using UDP and TCP protocols.

        Parameters:
            rdtype (str): The type of DNS record to retrieve.
            value (str): The value for which the DNS record is to be retrieved.

        Returns:
            dns.resolver.Answer: The DNS answer containing the resolved records.

        Raises:
            dns.resolver.NXDOMAIN: If the domain does not exist.
            dns.resolver.NoAnswer: If the domain exists but does not have the specified record type.
            dns.resolver.NoNameservers: If no nameservers are found for the domain.
            dns.exception.DNSException: For any other DNS-related exceptions.
        """
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [self.dnsserver]
        dns_answer = None
        # Try UDP
        try:
            dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=False)
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
                dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=True)
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

        if self.verbose and dns_answer is not None:
            for record in dns_answer:
                print(
                    "[debug] '%s' record found for %s: %s"
                    % (rdtype, value, record.address)
                )

        return dns_answer

    def check_presence_of_wildcard_dns(self):
        """
        Check the presence of wildcard DNS entries in the Microsoft DNS server.

        This function queries the Microsoft DNS server to find wildcard DNS entries in the DomainDnsZones of the specified domain.
        It retrieves information about wildcard DNS entries and prints a warning message if any are found.

        Returns:
            dict: A dictionary containing information about wildcard DNS entries found in the Microsoft DNS server.
        """

        ldap_server, ldap_session = init_ldap_session(
            auth_domain=self.auth_domain,
            auth_dc_ip=self.auth_dc_ip,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_lm_hash=self.auth_lm_hash,
            auth_nt_hash=self.auth_nt_hash,
            use_ldaps=self.use_ldaps,
        )

        target_dn = (
            "CN=MicrosoftDNS,DC=DomainDnsZones,"
            + ldap_server.info.other["rootDomainNamingContext"][0]
        )

        ldapresults = list(
            ldap_session.extend.standard.paged_search(
                target_dn,
                "(&(objectClass=dnsNode)(dc=\\2A))",
                attributes=["distinguishedName", "dNSTombstoned"],
            )
        )

        results = {}
        for entry in ldapresults:
            if entry["type"] != "searchResEntry":
                continue
            results[entry["dn"]] = entry["attributes"]

        if len(results.keys()) != 0:
            print(
                "[!] WARNING! Wildcard DNS entries found, dns resolution will not be consistent."
            )
            for dn, data in results.items():
                fqdn = re.sub(
                    ",CN=MicrosoftDNS,DC=DomainDnsZones,DC=DOMAIN,DC=local$", "", dn
                )
                fqdn = ".".join([dc.split("=")[1] for dc in fqdn.split(",")])

                ips = self.resolve(fqdn)

                if data["dNSTombstoned"]:
                    print("  | %s ──> %s (set to be removed)" % (dn, ips))
                else:
                    print("  | %s ──> %s" % (dn, ips))

                # Cache found wildcard dns
                for ip in ips:
                    if fqdn not in self.__wildcard_dns_cache.keys():
                        self.__wildcard_dns_cache[fqdn] = {}
                    if ip not in self.__wildcard_dns_cache[fqdn].keys():
                        self.__wildcard_dns_cache[fqdn][ip] = []
                    self.__wildcard_dns_cache[fqdn][ip].append(data)
            print()
        return results
