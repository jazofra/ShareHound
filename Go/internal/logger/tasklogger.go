// Package logger provides logging functionality for ShareHound.
package logger

import (
	"fmt"
	"strings"
	"time"

	"github.com/specterops/sharehound/internal/config"
)

// TaskLogger provides task-specific logging with isolated indentation.
// Each concurrent task gets its own TaskLogger to avoid indent conflicts.
type TaskLogger struct {
	baseLogger  *Logger
	taskID      string
	indentLevel int
}

// NewTaskLogger creates a new TaskLogger wrapping a base Logger.
func NewTaskLogger(baseLogger *Logger, taskID string) *TaskLogger {
	return &TaskLogger{
		baseLogger:  baseLogger,
		taskID:      taskID,
		indentLevel: 0,
	}
}

// getTimestampAndIndent returns formatted timestamp and indentation for this task.
func (t *TaskLogger) getTimestampAndIndent() (string, string) {
	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05")
	milliseconds := fmt.Sprintf(".%03d", now.Nanosecond()/1e6)
	timestampWithMs := timestamp + milliseconds
	indent := strings.Repeat("  │ ", t.indentLevel)
	return timestampWithMs, indent
}

// formatMessage formats a log message with task-specific context.
func (t *TaskLogger) formatMessage(message, level, colorCode string) string {
	timestamp, indent := t.getTimestampAndIndent()
	noColorMessage := stripAnsiCodes(message)

	taskPrefix := ""
	if t.taskID != "" {
		taskPrefix = "[" + t.taskID + "] "
	}

	if t.baseLogger.config.NoColors() {
		return fmt.Sprintf("[%s] [%s] %s%s%s", timestamp, level, taskPrefix, indent, noColorMessage)
	}

	if colorCode != "" {
		return fmt.Sprintf("[%s] [%s%s\x1b[0m] %s%s%s", timestamp, colorCode, level, taskPrefix, indent, message)
	}
	return fmt.Sprintf("[%s] [%s] %s%s%s", timestamp, level, taskPrefix, indent, message)
}

// Print prints a message to stdout and log file.
func (t *TaskLogger) Print(message string) {
	t.PrintWithEnd(message, "\n")
}

// PrintWithEnd prints a message with a custom line ending.
func (t *TaskLogger) PrintWithEnd(message string, end string) {
	formatted := t.formatMessage(message, "-----", "")
	fmt.Print(formatted + end)
	t.baseLogger.writeToLogFile(formatted, end)
}

// Info logs a message at the INFO level.
func (t *TaskLogger) Info(message string) {
	formatted := t.formatMessage(message, "info-", "\x1b[1;92m")
	fmt.Println(formatted)
	t.baseLogger.writeToLogFile(formatted, "\n")
}

// Debug logs a message at the DEBUG level if debugging is enabled.
func (t *TaskLogger) Debug(message string) {
	if !t.baseLogger.config.Debug() {
		return
	}
	formatted := t.formatMessage(message, "debug", "\x1b[1;93m")
	fmt.Println(formatted)
	t.baseLogger.writeToLogFile(formatted, "\n")
}

// Warning logs a message at the WARNING level.
func (t *TaskLogger) Warning(message string) {
	formatted := t.formatMessage(message, "warn-", "\x1b[1;95m")
	fmt.Println(formatted)
	t.baseLogger.writeToLogFile(formatted, "\n")
}

// Error logs a message at the ERROR level.
func (t *TaskLogger) Error(message string) {
	formatted := t.formatMessage(message, "error", "\x1b[1;91m")
	fmt.Println(formatted)
	t.baseLogger.writeToLogFile(formatted, "\n")
}

// Critical logs a message at the CRITICAL level.
func (t *TaskLogger) Critical(message string) {
	formatted := t.formatMessage(message, "crit-", "\x1b[1;91m")
	fmt.Println(formatted)
	t.baseLogger.writeToLogFile(formatted, "\n")
}

// IncrementIndent increases the indentation level for this task.
func (t *TaskLogger) IncrementIndent() {
	t.indentLevel++
}

// DecrementIndent decreases the indentation level for this task.
func (t *TaskLogger) DecrementIndent() {
	if t.indentLevel > 0 {
		t.indentLevel--
	}
}

// Config returns the underlying logger's config.
func (t *TaskLogger) Config() *config.Config {
	return t.baseLogger.config
}

// LoggerInterface defines the common interface for Logger and TaskLogger.
type LoggerInterface interface {
	Print(message string)
	PrintWithEnd(message string, end string)
	Info(message string)
	Debug(message string)
	Warning(message string)
	Error(message string)
	Critical(message string)
	IncrementIndent()
	DecrementIndent()
	Config() *config.Config
}

// Ensure both types implement LoggerInterface
var _ LoggerInterface = (*Logger)(nil)
var _ LoggerInterface = (*TaskLogger)(nil)
