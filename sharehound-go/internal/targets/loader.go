// Package targets provides target enumeration functionality.
package targets

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/utils"
)

// Target represents a scan target.
type Target struct {
	Type  string // "ipv4", "ipv6", "fqdn"
	Value string
}

// Options holds target loading options.
type Options struct {
	TargetsFile  string
	Targets      []string
	AuthDomain   string
	AuthDCIP     string
	AuthUser     string
	AuthPassword string
	AuthHashes   string
	AuthKey      string
	UseKerberos  bool
	KDCHost      string
	UseLDAPS     bool
	Subnets      bool
	Timeout      time.Duration
}

// LoadTargets loads and parses targets from various sources.
func LoadTargets(opts *Options, cfg *config.Config, log logger.LoggerInterface) ([]Target, error) {
	var rawTargets []string

	// Check if DC is reachable for LDAP queries
	if opts.AuthDCIP != "" && opts.AuthUser != "" && (opts.AuthPassword != "" || opts.AuthHashes != "") {
		port := 389
		if opts.UseLDAPS {
			port = 636
		}
		ok, _ := utils.IsPortOpen(opts.AuthDCIP, port, 10*time.Second)
		if !ok {
			log.Error("Domain controller " + opts.AuthDCIP + " is not reachable")
			return nil, nil
		}
	}

	// Load from file
	if opts.TargetsFile != "" {
		log.Debug("Loading targets from file: " + opts.TargetsFile)
		fileTargets, err := loadFromFile(opts.TargetsFile)
		if err != nil {
			log.Error("Error loading targets file: " + err.Error())
		} else {
			rawTargets = append(rawTargets, fileTargets...)
		}
	}

	// Load from CLI options
	if len(opts.Targets) > 0 {
		log.Debug("Loading targets from CLI options")
		rawTargets = append(rawTargets, opts.Targets...)
	}

	// Load from AD if no explicit targets
	if len(rawTargets) == 0 && opts.AuthDCIP != "" && opts.AuthUser != "" {
		log.Info("No target list specified, would fetch from Active Directory (not implemented)")
		// TODO: Implement LDAP queries for computers and servers
		// computers := getComputersFromDomain(opts)
		// servers := getServersFromDomain(opts)
	}

	// Load subnets if requested
	if opts.Subnets && opts.AuthDCIP != "" {
		log.Debug("Loading subnets from domain (not implemented)")
		// TODO: Implement subnet enumeration
	}

	// Deduplicate and sort
	rawTargets = uniqueStrings(rawTargets)

	// Parse and classify targets
	var finalTargets []Target
	for _, t := range rawTargets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		if utils.IsIPv4CIDR(t) {
			// Expand CIDR
			ips, err := utils.ExpandCIDR(t)
			if err != nil {
				log.Debug("Error expanding CIDR " + t + ": " + err.Error())
				continue
			}
			for _, ip := range ips {
				finalTargets = append(finalTargets, Target{Type: "ipv4", Value: ip})
			}
		} else if utils.IsIPv4Addr(t) {
			finalTargets = append(finalTargets, Target{Type: "ipv4", Value: t})
		} else if utils.IsIPv6Addr(t) {
			finalTargets = append(finalTargets, Target{Type: "ipv6", Value: t})
		} else if utils.IsFQDN(t) {
			finalTargets = append(finalTargets, Target{Type: "fqdn", Value: t})
		} else {
			log.Debug("Target '" + t + "' was not added (unknown type)")
		}
	}

	// Deduplicate final targets
	finalTargets = uniqueTargets(finalTargets)

	return finalTargets, nil
}

// loadFromFile loads targets from a file, one per line.
func loadFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// uniqueStrings returns unique strings sorted.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

// uniqueTargets returns unique targets sorted.
func uniqueTargets(input []Target) []Target {
	seen := make(map[string]bool)
	var result []Target
	for _, t := range input {
		key := t.Type + ":" + t.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, t)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].Value < result[j].Value
	})
	return result
}
