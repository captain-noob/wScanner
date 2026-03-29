package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrorLogger provides structured, thread-safe error logging to a file.
// It captures scan errors with context (target, port, phase) and also
// serves as an io.Writer to intercept Go's default logger output
// (e.g. HTTP transport warnings like "Unsolicited response received").
type ErrorLogger struct {
	file *os.File
	mu   sync.Mutex
}

// NewErrorLogger creates an error.log file in the given folder.
// Returns nil if the file cannot be created — callers must nil-check.
func NewErrorLogger(folder string) *ErrorLogger {
	fname := folder + "/error.log"
	f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("%s[!] Warning:%s Could not create error.log: %v\n", Yellow, Reset, err)
		return nil
	}
	return &ErrorLogger{file: f}
}

// Log writes a structured error entry to the log file.
//
//	target  — IP or hostname being scanned
//	port    — port number (may be empty)
//	errMsg  — the error description
//	context — scan phase (e.g. "port_scan", "scheme_detection", "http_probe", "recheck", "fuzzing", "enrichment")
func (el *ErrorLogger) Log(target, port, errMsg, context string) {
	if el == nil || el.file == nil {
		return
	}
	el.mu.Lock()
	defer el.mu.Unlock()

	ts := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] target=%s port=%s context=%s error=%q\n",
		ts, target, port, context, errMsg)
	el.file.WriteString(entry)
}

// Write implements io.Writer so ErrorLogger can be used with log.SetOutput().
// This intercepts noisy messages from Go's HTTP transport layer and writes
// them to error.log instead of polluting stdout.
func (el *ErrorLogger) Write(p []byte) (n int, err error) {
	if el == nil || el.file == nil {
		return len(p), nil // swallow silently if no file
	}
	el.mu.Lock()
	defer el.mu.Unlock()

	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	ts := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] target=- port=- context=http_transport error=%q\n", ts, msg)
	el.file.WriteString(entry)
	return len(p), nil
}

// Close flushes and closes the underlying log file.
func (el *ErrorLogger) Close() {
	if el == nil || el.file == nil {
		return
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	el.file.Close()
}
