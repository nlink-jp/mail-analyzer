// Package parser provides unified email parsing for EML and MSG formats.
// Adapted from eml-to-jsonl and msg-to-jsonl with SHA-256 hashing.
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Email is the structured representation of a parsed email message.
type Email struct {
	Source    string `json:"source"`
	Hash     string `json:"hash"` // SHA-256 of the raw input file
	MessageID string `json:"message_id,omitempty"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	From      string `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	CC        []string `json:"cc,omitempty"`
	BCC       []string `json:"bcc,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Date      string `json:"date,omitempty"`
	ReturnPath string `json:"return_path,omitempty"`
	ReplyTo    string `json:"reply_to,omitempty"`
	XMailer    string `json:"x_mailer,omitempty"`
	Received   []string `json:"received,omitempty"`
	AuthResults string `json:"authentication_results,omitempty"`
	Encoding   string `json:"encoding,omitempty"`
	Body       []BodyPart `json:"body"`
	Attachments []Attachment `json:"attachments"`
}

// BodyPart represents a single decoded body section.
type BodyPart struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// Attachment holds metadata and hash for an attached file.
type Attachment struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type"`
	Size     int    `json:"size"`
	Hash     string `json:"hash"` // SHA-256 of decoded attachment data
}

// PlainTextBody returns the concatenated plain text body parts.
func (e *Email) PlainTextBody() string {
	var parts []string
	for _, bp := range e.Body {
		if bp.Type == "text/plain" {
			parts = append(parts, bp.Content)
		}
	}
	return strings.Join(parts, "\n")
}

// HTMLBody returns the concatenated HTML body parts.
func (e *Email) HTMLBody() string {
	var parts []string
	for _, bp := range e.Body {
		if bp.Type == "text/html" {
			parts = append(parts, bp.Content)
		}
	}
	return strings.Join(parts, "\n")
}

// ParseFile reads and parses an email file, dispatching by extension.
func ParseFile(path string) (*Email, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseBytes(data, filepath.Base(path))
}

// ParseBytes parses email bytes, dispatching by filename extension.
func ParseBytes(data []byte, filename string) (*Email, error) {
	fileHash := sha256sum(data)

	lower := strings.ToLower(filename)
	var email *Email
	var err error

	switch {
	case strings.HasSuffix(lower, ".msg"):
		email, err = parseMSG(data, filename)
	case strings.HasSuffix(lower, ".eml"):
		email, err = parseEML(data, filename)
	default:
		return nil, fmt.Errorf("unsupported file extension: %s (expected .eml or .msg)", filename)
	}

	if err != nil {
		return nil, err
	}
	email.Hash = fileHash
	return email, nil
}

// ParseReader reads from an io.Reader and parses as EML.
func ParseReader(r io.Reader, source string) (*Email, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	email, err := parseEML(data, source)
	if err != nil {
		return nil, err
	}
	email.Hash = sha256sum(data)
	return email, nil
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
