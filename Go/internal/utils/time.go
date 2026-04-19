// Package utils provides utility functions for ShareHound.
package utils

import (
	"fmt"
	"time"
)

// DeltaTime formats a duration as a human-readable string.
// Format: "Xh Ym Zs" or "Ym Zs" or "Zs" depending on duration.
func DeltaTime(d time.Duration) string {
	totalSeconds := int(d.Seconds())

	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// DeltaTimeFloat formats a duration in seconds as a human-readable string.
func DeltaTimeFloat(seconds float64) string {
	return DeltaTime(time.Duration(seconds * float64(time.Second)))
}

// FormatTimestamp formats a time.Time as "YYYY-MM-DD HH:MM:SS.mmm".
func FormatTimestamp(t time.Time) string {
	return t.Format("2006-01-02 15:04:05") + fmt.Sprintf(".%03d", t.Nanosecond()/1e6)
}

// NowTimestamp returns the current timestamp formatted.
func NowTimestamp() string {
	return FormatTimestamp(time.Now())
}
