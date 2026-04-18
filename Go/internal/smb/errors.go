// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"errors"
	"strings"
)

// Common SMB/NT Status codes
const (
	STATUS_NOT_SUPPORTED       uint32 = 0xc00000bb
	STATUS_ACCESS_DENIED       uint32 = 0xc0000022
	STATUS_LOGON_FAILURE       uint32 = 0xc000006d
	STATUS_ACCOUNT_DISABLED    uint32 = 0xc0000072
	STATUS_ACCOUNT_LOCKED_OUT  uint32 = 0xc0000234
	STATUS_PASSWORD_EXPIRED    uint32 = 0xc0000071
	STATUS_INVALID_LOGON_HOURS uint32 = 0xc000006f
	STATUS_INVALID_WORKSTATION uint32 = 0xc0000070
	STATUS_ACCOUNT_RESTRICTION uint32 = 0xc000006e
	STATUS_BAD_NETWORK_NAME    uint32 = 0xc00000cc
	STATUS_CONNECTION_REFUSED  uint32 = 0xc0000236
	STATUS_NETWORK_UNREACHABLE uint32 = 0xc000023c
	STATUS_HOST_UNREACHABLE    uint32 = 0xc000023d
)

// Error categories
const (
	ErrorCategoryProtocol = "PROTOCOL"
	ErrorCategoryAuth     = "AUTH"
	ErrorCategoryNetwork  = "NETWORK"
	ErrorCategoryUnknown  = "UNKNOWN"
)

// ErrorClassification contains information about a classified SMB error.
type ErrorClassification struct {
	Category    string
	Message     string
	ShouldRetry bool
}

// ClassifyError classifies an SMB error for better handling.
func ClassifyError(err error) ErrorClassification {
	if err == nil {
		return ErrorClassification{
			Category:    ErrorCategoryUnknown,
			Message:     "no error",
			ShouldRetry: false,
		}
	}

	errStr := strings.ToLower(err.Error())

	// Check for protocol/dialect issues
	if strings.Contains(errStr, "not supported") ||
		strings.Contains(errStr, "dialect") ||
		strings.Contains(errStr, "unsupported") {
		return ErrorClassification{
			Category:    ErrorCategoryProtocol,
			Message:     "SMB dialect or feature not supported by server",
			ShouldRetry: true,
		}
	}

	// Check for authentication failures
	if strings.Contains(errStr, "logon failure") ||
		strings.Contains(errStr, "invalid username") ||
		strings.Contains(errStr, "invalid password") ||
		strings.Contains(errStr, "authentication") {
		return ErrorClassification{
			Category:    ErrorCategoryAuth,
			Message:     "Invalid username or password",
			ShouldRetry: false,
		}
	}

	if strings.Contains(errStr, "access denied") {
		return ErrorClassification{
			Category:    ErrorCategoryAuth,
			Message:     "Access denied - insufficient privileges",
			ShouldRetry: false,
		}
	}

	if strings.Contains(errStr, "account disabled") {
		return ErrorClassification{
			Category:    ErrorCategoryAuth,
			Message:     "Account is disabled",
			ShouldRetry: false,
		}
	}

	if strings.Contains(errStr, "locked out") {
		return ErrorClassification{
			Category:    ErrorCategoryAuth,
			Message:     "Account is locked out",
			ShouldRetry: false,
		}
	}

	if strings.Contains(errStr, "password expired") {
		return ErrorClassification{
			Category:    ErrorCategoryAuth,
			Message:     "Password has expired",
			ShouldRetry: false,
		}
	}

	// Check for network issues
	if strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "unreachable") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "timed out") {
		return ErrorClassification{
			Category:    ErrorCategoryNetwork,
			Message:     "Network connectivity issue",
			ShouldRetry: false,
		}
	}

	if strings.Contains(errStr, "bad network name") ||
		strings.Contains(errStr, "share not found") {
		return ErrorClassification{
			Category:    ErrorCategoryNetwork,
			Message:     "Share or network name not found",
			ShouldRetry: false,
		}
	}

	// Unknown error - might be worth retrying
	return ErrorClassification{
		Category:    ErrorCategoryUnknown,
		Message:     err.Error(),
		ShouldRetry: true,
	}
}

// Common errors
var (
	ErrNotConnected                   = errors.New("not connected to SMB server")
	ErrShareNotSet                    = errors.New("share not set")
	ErrConnectionFailed               = errors.New("failed to connect to SMB server")
	ErrAuthFailed                     = errors.New("authentication failed")
	ErrShareNotFound                  = errors.New("share not found")
	ErrAccessDenied                   = errors.New("access denied")
	ErrPathNotFound                   = errors.New("path not found")
	ErrSecurityDescriptorNotSupported = errors.New("security descriptor query not supported")
)
