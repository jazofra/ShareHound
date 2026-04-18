// Package utils provides utility functions for ShareHound.
package utils

import (
	"fmt"
)

// units for file size formatting
var sizeUnits = []string{"B", "kB", "MB", "GB", "TB", "PB"}

// FormatFileSize converts a file size in bytes to a human-readable format.
func FormatFileSize(size int64) string {
	if size == 0 {
		return "0 B"
	}

	floatSize := float64(size)
	unitIndex := 0

	for unitIndex < len(sizeUnits)-1 && floatSize >= 1024 {
		floatSize /= 1024
		unitIndex++
	}

	return fmt.Sprintf("%4.2f %s", floatSize, sizeUnits[unitIndex])
}

// ParseSizeFilter parses a size filter string like "+1M", "-500K", "100".
// Returns the threshold in bytes and the comparison operator.
func ParseSizeFilter(filter string) (int64, string, error) {
	if len(filter) == 0 {
		return 0, "", fmt.Errorf("empty filter")
	}

	operator := "="
	start := 0

	if filter[0] == '+' {
		operator = ">="
		start = 1
	} else if filter[0] == '-' {
		operator = "<="
		start = 1
	}

	if start >= len(filter) {
		return 0, "", fmt.Errorf("invalid filter: %s", filter)
	}

	// Find where the number ends
	numEnd := start
	for numEnd < len(filter) && filter[numEnd] >= '0' && filter[numEnd] <= '9' {
		numEnd++
	}

	if numEnd == start {
		return 0, "", fmt.Errorf("no number in filter: %s", filter)
	}

	// Parse the number
	var number int64
	_, err := fmt.Sscanf(filter[start:numEnd], "%d", &number)
	if err != nil {
		return 0, "", err
	}

	// Get the unit
	unit := ""
	if numEnd < len(filter) {
		unit = string(filter[numEnd])
	}

	// Convert to bytes
	multipliers := map[string]int64{
		"":  1,
		"B": 1,
		"K": 1024,
		"M": 1024 * 1024,
		"G": 1024 * 1024 * 1024,
		"T": 1024 * 1024 * 1024 * 1024,
		"P": 1024 * 1024 * 1024 * 1024 * 1024,
	}

	// Case-insensitive unit lookup
	unitUpper := ""
	if len(unit) > 0 {
		if unit[0] >= 'a' && unit[0] <= 'z' {
			unitUpper = string(unit[0] - 32)
		} else {
			unitUpper = unit
		}
	}

	multiplier, ok := multipliers[unitUpper]
	if !ok {
		multiplier = 1
	}

	return number * multiplier, operator, nil
}

// MatchesSizeFilter checks if a size matches the given filter.
func MatchesSizeFilter(size int64, filter string) bool {
	threshold, operator, err := ParseSizeFilter(filter)
	if err != nil {
		return false
	}

	switch operator {
	case ">=":
		return size >= threshold
	case "<=":
		return size <= threshold
	case "=":
		return size == threshold
	default:
		return false
	}
}
