// Package utils provides utility functions for ShareHound.
package utils

import (
	"context"
	"fmt"
	"net"
	"time"
)

// IsPortOpen checks if a specific port on a target host is open.
// Returns true if the port is open, otherwise false and an error message.
func IsPortOpen(target string, port int, timeout time.Duration) (bool, error) {
	address := fmt.Sprintf("%s:%d", target, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}

	conn.Close()
	return true, nil
}

// IsIPv4Addr checks if a string is a valid IPv4 address.
func IsIPv4Addr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

// IsIPv6Addr checks if a string is a valid IPv6 address.
func IsIPv6Addr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() == nil && ip.To16() != nil
}

// IsIPv4CIDR checks if a string is a valid IPv4 CIDR notation.
func IsIPv4CIDR(s string) bool {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return ipnet.IP.To4() != nil
}

// ExpandCIDR expands a CIDR notation to a list of IP addresses.
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /31 and larger networks
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// incIP increments an IP address by one.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IsFQDN checks if a string appears to be a fully qualified domain name.
func IsFQDN(s string) bool {
	// Basic check: contains at least one dot and no spaces
	if len(s) == 0 || len(s) > 255 {
		return false
	}

	// Should contain at least one dot
	hasDot := false
	for _, c := range s {
		if c == '.' {
			hasDot = true
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return false
		}
	}

	if !hasDot {
		return false
	}

	// Should not be an IP address
	if IsIPv4Addr(s) || IsIPv6Addr(s) {
		return false
	}

	return true
}
