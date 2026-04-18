// Package utils provides utility functions for ShareHound.
package utils

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSResolve resolves a domain name to an IP address using DNS.
// It tries UDP first, then falls back to TCP.
func DNSResolve(targetName string, nameserver string, dcIP string, timeout time.Duration) (string, error) {
	var server string
	if nameserver != "" {
		server = nameserver
	} else if dcIP != "" {
		server = dcIP
	} else {
		// Use system resolver
		return systemResolve(targetName, timeout)
	}

	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	// Try UDP first
	ip, err := dnsQuery(targetName, server, false, timeout)
	if err == nil && ip != "" {
		return ip, nil
	}

	// Try TCP as fallback
	ip, err = dnsQuery(targetName, server, true, timeout)
	if err == nil && ip != "" {
		return ip, nil
	}

	return "", err
}

// dnsQuery performs a DNS A record query.
func dnsQuery(name, server string, useTCP bool, timeout time.Duration) (string, error) {
	c := new(dns.Client)
	c.Timeout = timeout
	if useTCP {
		c.Net = "tcp"
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, server)
	if err != nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", nil
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", nil
}

// systemResolve uses the system resolver to resolve a hostname.
func systemResolve(hostname string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		return "", err
	}

	// Return the first IPv4 address
	for _, addr := range addrs {
		if IsIPv4Addr(addr) {
			return addr, nil
		}
	}

	// Return first address if no IPv4
	if len(addrs) > 0 {
		return addrs[0], nil
	}

	return "", nil
}
