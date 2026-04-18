// Package ldap provides LDAP client functionality for Active Directory queries.
package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Default page size for LDAP paging (AD default MaxPageSize is 1000)
const defaultPageSize = 1000

// Client represents an LDAP client for Active Directory.
type Client struct {
	conn     *ldap.Conn
	baseDN   string
	domain   string
	dcIP     string
	username string
	password string
	useLDAPS bool
	useNTLM  bool
	ntHash   string
}

// ClientOptions holds options for creating an LDAP client.
type ClientOptions struct {
	Domain      string
	DCIP        string
	Username    string
	Password    string
	Hashes      string // LM:NT format
	UseLDAPS    bool
	UseKerberos bool
	KDCHost     string
}

// NewClient creates a new LDAP client.
func NewClient(opts *ClientOptions) (*Client, error) {
	client := &Client{
		domain:   opts.Domain,
		dcIP:     opts.DCIP,
		username: opts.Username,
		password: opts.Password,
		useLDAPS: opts.UseLDAPS,
	}

	// Parse hashes if provided
	if opts.Hashes != "" {
		parts := strings.Split(opts.Hashes, ":")
		if len(parts) == 2 {
			client.ntHash = parts[1]
			client.useNTLM = true
		}
	}

	// Build base DN from domain
	client.baseDN = domainToBaseDN(opts.Domain)

	return client, nil
}

// Connect establishes connection to the LDAP server.
func (c *Client) Connect() error {
	var err error
	var conn *ldap.Conn

	if c.useLDAPS {
		// LDAPS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", c.dcIP), tlsConfig)
	} else {
		// Plain LDAP connection
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:389", c.dcIP))
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	c.conn = conn

	// Bind with credentials
	bindDN := fmt.Sprintf("%s@%s", c.username, c.domain)
	if err := c.conn.Bind(bindDN, c.password); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to bind to LDAP server: %w", err)
	}

	return nil
}

// Close closes the LDAP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// GetComputers retrieves all computer objects from AD using paging.
func (c *Client) GetComputers() ([]string, error) {
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	// Use paging to handle large result sets
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range sr.Entries {
		// Prefer dNSHostName, fall back to name
		dnsName := entry.GetAttributeValue("dNSHostName")
		if dnsName != "" {
			computers = append(computers, dnsName)
		} else {
			name := entry.GetAttributeValue("name")
			if name != "" {
				computers = append(computers, name)
			}
		}
	}

	return computers, nil
}

// GetServers retrieves server objects from AD (computers with "server" in OS) using paging.
func (c *Client) GetServers() ([]string, error) {
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	// Use paging to handle large result sets
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var servers []string
	for _, entry := range sr.Entries {
		dnsName := entry.GetAttributeValue("dNSHostName")
		if dnsName != "" {
			servers = append(servers, dnsName)
		} else {
			name := entry.GetAttributeValue("name")
			if name != "" {
				servers = append(servers, name)
			}
		}
	}

	return servers, nil
}

// GetSubnets retrieves subnet objects from AD Sites and Services.
func (c *Client) GetSubnets() ([]string, error) {
	// Subnets are stored in CN=Subnets,CN=Sites,CN=Configuration,<baseDN>
	configDN := "CN=Subnets,CN=Sites,CN=Configuration," + c.baseDN

	searchRequest := ldap.NewSearchRequest(
		configDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=subnet)",
		[]string{"cn", "name"},
		nil,
	)

	// Use paging for consistency, though subnets are usually fewer
	sr, err := c.conn.SearchWithPaging(searchRequest, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for subnets failed: %w", err)
	}

	var subnets []string
	for _, entry := range sr.Entries {
		// The CN of a subnet object is the CIDR notation (e.g., "10.0.0.0/24")
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			subnets = append(subnets, cn)
		}
	}

	return subnets, nil
}

// domainToBaseDN converts a domain name to LDAP base DN.
// e.g., "corp.local" -> "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	return strings.Join(dnParts, ",")
}
