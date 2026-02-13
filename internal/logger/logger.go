// Package logger provides logging functionality for ShareHound.
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/specterops/sharehound/internal/config"
)

// LogLevel represents the severity level of a log message.
type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
	WARNING
	ERROR
	CRITICAL
)

// Logger provides logging functionality with color support and file output.
type Logger struct {
	config      *config.Config
	logfile     *os.File
	logfilePath string
	indentLevel int
	mu          sync.Mutex
}

// NewLogger creates a new Logger instance.
func NewLogger(cfg *config.Config, logfilePath string) *Logger {
	l := &Logger{
		config:      cfg,
		indentLevel: 0,
	}

	if logfilePath != "" {
		l.openLogFile(logfilePath)
	}

	return l
}

// openLogFile opens a log file, handling rotation if the file exists.
func (l *Logger) openLogFile(path string) {
	finalPath := path

	if _, err := os.Stat(path); err == nil {
		// File exists, find a new name
		k := 1
		for {
			newPath := fmt.Sprintf("%s.%d", path, k)
			if _, err := os.Stat(newPath); os.IsNotExist(err) {
				finalPath = newPath
				break
			}
			k++
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(finalPath)
	if dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}

	file, err := os.Create(finalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not create log file %s: %v\n", finalPath, err)
		return
	}

	l.logfile = file
	l.logfilePath = finalPath
	l.Debug("Writing logs to logfile: '" + finalPath + "'")
}

// Close closes the log file if one is open.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logfile != nil {
		l.logfile.Close()
		l.logfile = nil
	}
}

// getTimestampAndIndent returns the formatted timestamp and indentation string.
func (l *Logger) getTimestampAndIndent() (string, string) {
	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05")
	milliseconds := fmt.Sprintf(".%03d", now.Nanosecond()/1e6)
	timestampWithMs := timestamp + milliseconds
	indent := strings.Repeat("  │ ", l.indentLevel)
	return timestampWithMs, indent
}

// stripAnsiCodes removes ANSI escape codes from a string.
func stripAnsiCodes(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]+m`)
	return re.ReplaceAllString(s, "")
}

// Print prints a message to stdout and logs it to file.
func (l *Logger) Print(message string) {
	l.PrintWithEnd(message, "\n")
}

// PrintWithEnd prints a message with a custom line ending.
func (l *Logger) PrintWithEnd(message string, end string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [-----] %s%s%s", timestamp, indent, noColorMessage, end)
	} else {
		fmt.Printf("[%s] [-----] %s%s%s", timestamp, indent, message, end)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] %s%s", timestamp, indent, noColorMessage), end)
}

// Info logs a message at the INFO level.
func (l *Logger) Info(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [info-] %s%s\n", timestamp, indent, noColorMessage)
	} else {
		fmt.Printf("[%s] [\x1b[1;92minfo-\x1b[0m] %s%s\n", timestamp, indent, message)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] [info] %s%s", timestamp, indent, noColorMessage), "\n")
}

// Debug logs a message at the DEBUG level if debugging is enabled.
func (l *Logger) Debug(message string) {
	if !l.config.Debug() {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [debug] %s%s\n", timestamp, indent, noColorMessage)
	} else {
		fmt.Printf("[%s] [\x1b[1;93mdebug\x1b[0m] %s%s\n", timestamp, indent, message)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] [debug] %s%s", timestamp, indent, noColorMessage), "\n")
}

// Warning logs a message at the WARNING level.
func (l *Logger) Warning(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [warn-] %s%s\n", timestamp, indent, noColorMessage)
	} else {
		fmt.Printf("[%s] [\x1b[1;95mwarn-\x1b[0m] %s%s\n", timestamp, indent, message)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] [warn] %s%s", timestamp, indent, noColorMessage), "\n")
}

// Error logs a message at the ERROR level.
func (l *Logger) Error(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [error] %s%s\n", timestamp, indent, noColorMessage)
	} else {
		fmt.Printf("[%s] [\x1b[1;91merror\x1b[0m] %s%s\n", timestamp, indent, message)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] [error] %s%s", timestamp, indent, noColorMessage), "\n")
}

// Critical logs a message at the CRITICAL level.
func (l *Logger) Critical(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp, indent := l.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	if l.config.NoColors() {
		fmt.Printf("[%s] [crit-] %s%s\n", timestamp, indent, noColorMessage)
	} else {
		fmt.Printf("[%s] [\x1b[1;91mcrit-\x1b[0m] %s%s\n", timestamp, indent, message)
	}

	l.writeToLogFile(fmt.Sprintf("[%s] [crit] %s%s", timestamp, indent, noColorMessage), "\n")
}

// IncrementIndent increases the indentation level.
func (l *Logger) IncrementIndent() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.indentLevel++
}

// DecrementIndent decreases the indentation level.
func (l *Logger) DecrementIndent() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.indentLevel > 0 {
		l.indentLevel--
	}
}

// writeToLogFile writes a message to the log file.
func (l *Logger) writeToLogFile(message, end string) {
	if l.logfile == nil {
		return
	}

	noColorMessage := stripAnsiCodes(message)
	io.WriteString(l.logfile, noColorMessage+end)
}

// Config returns the logger's config.
func (l *Logger) Config() *config.Config {
	return l.config
}
