//go:build !windows

package ldap

import (
	"fmt"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

func newWindowsGSSAPIClient() (ldapv3.GSSAPIClient, error) {
	return nil, fmt.Errorf("implicit Windows authentication is only supported on Windows")
}
