//go:build windows

package ldap

import (
	ldapv3 "github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
)

func newWindowsGSSAPIClient() (ldapv3.GSSAPIClient, error) {
	return ldapgssapi.NewSSPIClient()
}
