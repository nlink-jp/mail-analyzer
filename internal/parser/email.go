// Package parser reads .eml and .msg files with github.com/nlink-jp/mailparse
// and shapes the result into the Email the indicators and the LLM prompt read,
// adding SHA-256 hashes of the file and of each attachment.
package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nlink-jp/mailparse"
)

// Email is the structured representation of a parsed email message.
//
// The string fields are display forms. The rules read the structured fields
// (FromFields, ReplyToMailboxes, ReturnPaths, AllAuthResults) when they are
// set; an Email built by hand with only the strings still works.
type Email struct {
	Source      string       `json:"source"`
	Hash        string       `json:"hash"` // SHA-256 of the raw input file
	MessageID   string       `json:"message_id,omitempty"`
	InReplyTo   string       `json:"in_reply_to,omitempty"`
	From        string       `json:"from,omitempty"` // the first From field
	To          []string     `json:"to,omitempty"`
	CC          []string     `json:"cc,omitempty"`
	BCC         []string     `json:"bcc,omitempty"`
	Subject     string       `json:"subject,omitempty"`
	Date        string       `json:"date,omitempty"`
	ReturnPath  string       `json:"return_path,omitempty"`
	ReplyTo     string       `json:"reply_to,omitempty"`
	XMailer     string       `json:"x_mailer,omitempty"`
	Received    []string     `json:"received,omitempty"`
	AuthResults string       `json:"authentication_results,omitempty"` // the first field
	Encoding    string       `json:"encoding,omitempty"`
	Body        []BodyPart   `json:"body"`
	Attachments []Attachment `json:"attachments"`

	// FromFields holds every From field in order, each with all its
	// mailboxes: a duplicated From is two entries.
	FromFields       [][]Mailbox `json:"from_fields,omitempty"`
	ReplyToMailboxes []Mailbox   `json:"reply_to_mailboxes,omitempty"`
	// ReturnPaths holds the address of each Return-Path field ("" for "<>").
	ReturnPaths []string `json:"return_paths,omitempty"`
	// AllAuthResults holds every Authentication-Results field, in order.
	AllAuthResults []string `json:"all_authentication_results,omitempty"`
	// Warnings are what mailparse met while reading this message.
	Warnings []Warning `json:"warnings,omitempty"`
	// Nested holds the attached messages that were opened (message/rfc822,
	// a forwarded .eml/.msg, an embedded .msg, winmail.dat).
	Nested []*Email `json:"nested,omitempty"`
	// Part is where this message sits in its parent ("" for the top one).
	Part string `json:"part,omitempty"`

	// msg is the message this Email was shaped from; nil for one built by hand.
	msg *mailparse.Message
}

// Mailbox is one parsed address. Name is the decoded display name: attacker
// text that may itself look like an address.
type Mailbox struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// Warning is one thing mailparse met and handled (a stable code, its own
// wording, and where in the message).
type Warning struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
	Part   string `json:"part,omitempty"`
}

// BodyPart represents a single decoded body section.
type BodyPart struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	// Part is where the body came from: a MIME part path, or for a .msg or
	// TNEF the property ("msg/body", "msg/html", "msg/rtf").
	Part string `json:"part,omitempty"`
	// Origin is mailparse's kind of source: "mime", "mapi", "rtf" (Outlook's
	// compressed RTF) or "tnef".
	Origin string `json:"origin,omitempty"`
}

// fromRTF reports whether the body was taken out of Outlook's compressed RTF.
func (bp BodyPart) fromRTF() bool { return bp.Origin == "rtf" }

// Attachment holds metadata and hash for an attached file.
type Attachment struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type"`
	Size     int    `json:"size"`
	Hash     string `json:"hash"` // SHA-256 of decoded attachment data; "" when no bytes were extracted
	Part     string `json:"part,omitempty"`
}

// PlainTextBody returns the concatenated plain text body parts.
func (e *Email) PlainTextBody() string { return e.bodyOfType("text/plain") }

// HTMLBody returns the concatenated HTML body parts.
func (e *Email) HTMLBody() string { return e.bodyOfType("text/html") }

// bodyOfType joins the bodies of one type. A .msg holds the same text more
// than once (the body property and the compressed RTF); the RTF-derived copy
// is left out when another body of the type exists, so the LLM's excerpt is
// not spent on a duplicate. URL checks still read every body.
func (e *Email) bodyOfType(mediaType string) string {
	other := false
	for _, bp := range e.Body {
		if bp.Type == mediaType && !bp.fromRTF() {
			other = true
		}
	}
	var parts []string
	for _, bp := range e.Body {
		if bp.Type == mediaType && (!other || !bp.fromRTF()) {
			parts = append(parts, bp.Content)
		}
	}
	return strings.Join(parts, "\n")
}

// AllWarnings returns this message's warnings followed by those of every
// nested message, the latter with their Part made absolute ("2>1" is part 1 of
// the message attached as 2, "2" its header), as mailparse's
// Message.AllWarnings gives them. An Email built by hand gives its own
// Warnings.
func (e *Email) AllWarnings() []Warning {
	if e.msg == nil {
		return e.Warnings
	}
	return warnings(e.msg.AllWarnings())
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
	var opt mailparse.Options // MaxSize: mailparse.DefaultMaxSize (64 MiB)
	lower := strings.ToLower(filename)
	var m *mailparse.Message
	var err error
	switch {
	case strings.HasSuffix(lower, ".msg"):
		m, err = mailparse.ParseMSG(bytes.NewReader(data), opt)
	case strings.HasSuffix(lower, ".eml"):
		m, err = mailparse.ParseEML(bytes.NewReader(data), opt)
	default:
		return nil, fmt.Errorf("unsupported file extension: %s (expected .eml or .msg)", filename)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filename, err)
	}
	email := FromMessage(m, filename)
	email.Hash = sha256sum(data)
	return email, nil
}

// ParseReader reads from an io.Reader and parses as EML.
func ParseReader(r io.Reader, source string) (*Email, error) {
	data, err := io.ReadAll(io.LimitReader(r, mailparse.DefaultMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	m, err := mailparse.ParseEML(bytes.NewReader(data), mailparse.Options{})
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}
	email := FromMessage(m, source)
	email.Hash = sha256sum(data)
	return email, nil
}

// FromMessage shapes a parsed message into an Email. Hash is left to the
// caller, who holds the raw bytes.
func FromMessage(m *mailparse.Message, source string) *Email {
	e := &Email{
		Source:      source,
		MessageID:   strings.TrimSpace(m.MessageID),
		Subject:     m.Subject,
		Body:        []BodyPart{},
		Attachments: []Attachment{},
		msg:         m,
	}
	h := m.Header
	e.InReplyTo = firstValue(h, "In-Reply-To")
	e.XMailer = firstValue(h, "X-Mailer")
	e.ReturnPath = firstValue(h, "Return-Path")
	for _, f := range h.All("Received") {
		// Folding whitespace is joined into one space, as net/textproto
		// did: the routing rules match "by " and would miss "by\t".
		e.Received = append(e.Received, f.Collapsed())
	}
	for _, f := range h.All("Authentication-Results") {
		e.AllAuthResults = append(e.AllAuthResults, strings.TrimSpace(f.Value))
	}
	if len(e.AllAuthResults) > 0 {
		e.AuthResults = e.AllAuthResults[0]
	}

	switch {
	case !m.Date.IsZero():
		e.Date = m.Date.Format(time.RFC3339)
	default:
		e.Date = strings.TrimSpace(m.DateRaw)
	}

	for i, al := range m.From {
		e.FromFields = append(e.FromFields, mailboxes(al))
		if i == 0 {
			e.From = displayList(al)
		}
	}
	for _, al := range m.ReplyTo {
		e.ReplyToMailboxes = append(e.ReplyToMailboxes, mailboxes(al)...)
	}
	var replyTo []string
	for _, al := range m.ReplyTo {
		replyTo = append(replyTo, displayField(al)...)
	}
	e.ReplyTo = strings.Join(replyTo, ", ")
	for _, al := range m.ReturnPath {
		addr := ""
		if len(al.Mailboxes) > 0 {
			addr = al.Mailboxes[0].Address
		}
		e.ReturnPaths = append(e.ReturnPaths, addr)
	}
	if e.ReturnPath == "" && len(m.ReturnPath) > 0 {
		e.ReturnPath = collapse(m.ReturnPath[0].Raw)
	}
	e.To = displayAll(m.To)
	e.CC = displayAll(m.Cc)
	e.BCC = displayAll(m.Bcc)

	for _, b := range m.Bodies {
		e.Body = append(e.Body, BodyPart{Type: b.MediaType, Content: toLF(b.Content), Part: b.Part, Origin: b.Origin})
		if e.Encoding == "" && b.Charset != "" && !isUTF8OrASCII(b.Charset) {
			e.Encoding = strings.ToUpper(b.Charset)
		}
	}

	for _, a := range m.Attachments {
		if isInlineText(a) {
			// mailparse makes bodies of text/plain and text/html only; another
			// unnamed inline text part (a text/calendar invite...) was a body
			// before and its links were checked, so it stays one, converted to
			// UTF-8 by the rules bodies use.
			e.Body = append(e.Body, BodyPart{Type: a.MediaType, Content: toLF(a.Text().Content), Part: a.Part, Origin: "mime"})
			continue
		}
		filename := a.Filename
		if filename == "" {
			filename = "attachment"
		}
		att := Attachment{
			Filename: filename,
			MIMEType: a.MediaType,
			Size:     a.Size,
			Part:     a.Part,
		}
		if a.Data != nil {
			att.Hash = sha256sum(a.Data)
		}
		e.Attachments = append(e.Attachments, att)
		if a.Message != nil {
			n := FromMessage(a.Message, source+"#"+a.Part)
			n.Part = a.Part
			if a.Data != nil {
				n.Hash = att.Hash
			}
			e.Nested = append(e.Nested, n)
		}
	}

	e.Warnings = warnings(m.Warnings)
	return e
}

func warnings(ws []mailparse.Warning) []Warning {
	var out []Warning
	for _, w := range ws {
		out = append(out, Warning{Code: w.Code, Detail: w.Detail, Part: w.Part})
	}
	return out
}

// isInlineText reports an unnamed text part not marked as an attachment, which
// the in-house parser read as a body.
func isInlineText(a mailparse.Attachment) bool {
	return strings.HasPrefix(a.MediaType, "text/") && a.Filename == "" &&
		a.Disposition != "attachment" && a.Message == nil && a.Data != nil
}

// toLF normalizes line ends to LF.
func toLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

func firstValue(h mailparse.Header, name string) string {
	if f, ok := h.First(name); ok {
		return strings.TrimSpace(f.Value)
	}
	return ""
}

func mailboxes(al mailparse.AddressList) []Mailbox {
	out := make([]Mailbox, 0, len(al.Mailboxes))
	for _, mb := range al.Mailboxes {
		out = append(out, Mailbox{Name: mb.Name, Address: mb.Address})
	}
	return out
}

// displayField renders one address field as one string per mailbox, or as
// its raw value when a mailbox has no address (an Exchange "/O=..." DN stays
// visible that way) or none could be read.
func displayField(al mailparse.AddressList) []string {
	mbs := mailboxes(al)
	usable := len(mbs) > 0
	for _, mb := range mbs {
		if mb.Address == "" {
			usable = false
		}
	}
	if !usable {
		if raw := collapse(al.Raw); raw != "" {
			return []string{raw}
		}
		return nil
	}
	out := make([]string, len(mbs))
	for i, mb := range mbs {
		out[i] = mb.String()
	}
	return out
}

// displayList renders one address field as one string.
func displayList(al mailparse.AddressList) string {
	return strings.Join(displayField(al), ", ")
}

func displayAll(lists []mailparse.AddressList) []string {
	var out []string
	for _, al := range lists {
		out = append(out, displayField(al)...)
	}
	return out
}

// collapse joins the folded lines of a raw address field into one; a Field
// has Collapsed for this, an AddressList's Raw does not.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// String renders the mailbox in RFC 5322 form with mailparse's Mailbox.String:
// a display name that is not plain atoms is quoted, so a name that looks like
// an address stays a name, and reading the result again gives this mailbox.
func (mb Mailbox) String() string {
	return mailparse.Mailbox{Name: mb.Name, Address: mb.Address}.String()
}

func isUTF8OrASCII(charset string) bool {
	switch strings.ToLower(charset) {
	case "utf-8", "us-ascii", "ascii":
		return true
	}
	return false
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
