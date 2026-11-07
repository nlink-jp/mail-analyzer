// Package parser reads an email (.eml, Outlook .msg, winmail.dat) with
// github.com/nlink-jp/mailparse and maps it onto the Email the indicators and
// the LLM prompt read. It holds no parsing of its own: every header, address,
// body and attachment comes from mailparse.
//
// This package is identical in mail-analyzer and mail-analyzer-local.
package parser

import (
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
type Email struct {
	Source     string   `json:"source"`
	Hash       string   `json:"hash"` // SHA-256 of the raw input file
	MessageID  string   `json:"message_id,omitempty"`
	InReplyTo  string   `json:"in_reply_to,omitempty"`
	References string   `json:"references,omitempty"`
	From       string   `json:"from,omitempty"` // every From mailbox, RFC 5322 form, joined by ", "
	To         []string `json:"to,omitempty"`
	CC         []string `json:"cc,omitempty"`
	BCC        []string `json:"bcc,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Date       string   `json:"date,omitempty"`
	ReturnPath string   `json:"return_path,omitempty"`
	ReplyTo    string   `json:"reply_to,omitempty"`
	XMailer    string   `json:"x_mailer,omitempty"`
	Received   []string `json:"received,omitempty"`
	// AuthResults holds every Authentication-Results field, in order.
	AuthResults []string            `json:"authentication_results,omitempty"`
	Encoding    string              `json:"encoding,omitempty"`
	Body        []BodyPart          `json:"body"`        // bodies of the outer message
	Attachments []Attachment        `json:"attachments"` // attachments of every layer
	Warnings    []mailparse.Warning `json:"warnings"`

	// Typed values the indicators read; never parse them back out of the
	// display strings above.
	FromMailboxes       []mailparse.Mailbox `json:"-"`
	ReturnPathMailboxes []mailparse.Mailbox `json:"-"`
	ReplyToMailboxes    []mailparse.Mailbox `json:"-"`
	// Texts are the further texts searched for URLs: the bodies of nested
	// messages and the text/* attachments of every layer.
	Texts []Text `json:"-"`
}

// BodyPart represents a single decoded body section.
type BodyPart struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	Origin  string `json:"origin,omitempty"` // mailparse Body.Origin: mime, mapi, rtf, tnef
}

// Attachment holds metadata and hash for an attached file.
type Attachment struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type"`
	Size     int    `json:"size"`
	Hash     string `json:"hash"`            // SHA-256 of decoded attachment data
	Layer    string `json:"layer,omitempty"` // mailparse Walk path of the message holding it; "" is the outer message
}

// Text is one further text searched for URLs.
type Text struct {
	Layer      string // mailparse Walk path of the message holding it
	Attachment string // the attachment's file name when the text is a text/* attachment
	Content    string
}

// PlainTextBody returns the concatenated plain text body parts.
func (e *Email) PlainTextBody() string { return e.joinBodies("text/plain") }

// HTMLBody returns the concatenated HTML body parts.
func (e *Email) HTMLBody() string { return e.joinBodies("text/html") }

func (e *Email) joinBodies(mediaType string) string {
	var parts []string
	for _, bp := range e.Body {
		if bp.Type == mediaType {
			parts = append(parts, bp.Content)
		}
	}
	return strings.Join(parts, "\n")
}

// ParseFile reads and parses an email file. The format is recognized by
// content, not by the file name.
func ParseFile(path string) (*Email, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	// One byte past the limit, so mailparse reports ErrTooLarge instead of
	// parsing a cut file.
	data, err := io.ReadAll(io.LimitReader(f, mailparse.DefaultMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseBytes(data, filepath.Base(path))
}

// ParseBytes parses email bytes (.eml, .msg or TNEF, recognized by content).
func ParseBytes(data []byte, source string) (*Email, error) {
	m, err := mailparse.ParseBytes(data, mailparse.Options{AssumeEML: true})
	if err != nil {
		return nil, err
	}
	email := FromMessage(m, source)
	email.Hash = sha256sum(data)
	return email, nil
}

// FromMessage maps a parsed message onto an Email.
func FromMessage(m *mailparse.Message, source string) *Email {
	e := &Email{
		Source:              source,
		MessageID:           m.MessageID,
		InReplyTo:           m.InReplyTo,
		References:          m.References,
		Subject:             m.Subject,
		Date:                formatDate(m),
		FromMailboxes:       mailboxes(m.From),
		ReturnPathMailboxes: mailboxes(m.ReturnPath),
		ReplyToMailboxes:    mailboxes(m.ReplyTo),
		To:                  mailboxStrings(m.To),
		CC:                  mailboxStrings(m.Cc),
		BCC:                 mailboxStrings(m.Bcc),
		Received:            collapsedAll(m.Header, "Received"),
		AuthResults:         collapsedAll(m.Header, "Authentication-Results"),
		Body:                []BodyPart{},
		Attachments:         []Attachment{},
		Warnings:            m.AllWarnings(),
	}
	if e.Warnings == nil {
		e.Warnings = []mailparse.Warning{}
	}
	e.From = joinMailboxes(e.FromMailboxes)
	e.ReplyTo = joinMailboxes(e.ReplyToMailboxes)
	e.ReturnPath = returnPath(m.ReturnPath)
	if f, ok := m.Header.First("X-Mailer"); ok {
		e.XMailer = f.Collapsed()
	}

	shown := bodies(m)
	for _, b := range shown {
		e.Body = append(e.Body, BodyPart{Type: b.MediaType, Content: b.Content, Origin: b.Origin})
	}
	e.Encoding = encoding(shown)
	// An outer body left out of Body (an RTF copy) is still searched for
	// URLs: Outlook may show the RTF, and it need not match the other body.
	if len(shown) < len(m.Bodies) {
		for _, b := range m.Bodies {
			if b.Origin == "rtf" {
				e.Texts = append(e.Texts, Text{Content: b.Content})
			}
		}
	}

	m.Walk(func(path string, _ int, msg *mailparse.Message) bool {
		if path != "" {
			// Every body of a nested message, RTF copies included: URL search
			// wants all of them, and duplicates are removed there.
			for _, b := range msg.Bodies {
				e.Texts = append(e.Texts, Text{Layer: path, Content: b.Content})
			}
		}
		for _, a := range msg.Attachments {
			e.Attachments = append(e.Attachments, Attachment{
				Filename: a.Filename,
				MIMEType: a.MediaType,
				Size:     a.Size,
				Hash:     sha256sum(a.Data),
				Layer:    path,
			})
			if strings.HasPrefix(a.MediaType, "text/") {
				e.Texts = append(e.Texts, Text{Layer: path, Attachment: a.Filename, Content: a.Text().Content})
			}
		}
		return true
	})
	return e
}

// bodies returns the bodies of one message to show, leaving out the bodies
// recovered from compressed RTF when the message has another body: in a .msg
// the RTF is normally a copy of PidTagBody or PidTagHtml.
func bodies(m *mailparse.Message) []mailparse.Body {
	var other, rtf []mailparse.Body
	for _, b := range m.Bodies {
		if b.Origin == "rtf" {
			rtf = append(rtf, b)
		} else {
			other = append(other, b)
		}
	}
	if len(other) > 0 {
		return other
	}
	return rtf
}

// encoding returns the first charset other than UTF-8 and US-ASCII, upper-cased.
// A .msg Unicode property (UTF-16LE) is the container's storage, not a charset
// the sender chose, and is skipped as before.
func encoding(bs []mailparse.Body) string {
	for _, b := range bs {
		if b.CharsetSource == "unicode" {
			continue
		}
		if b.Charset != "" && !strings.EqualFold(b.Charset, "utf-8") && !strings.EqualFold(b.Charset, "us-ascii") {
			return strings.ToUpper(b.Charset)
		}
	}
	return ""
}

func formatDate(m *mailparse.Message) string {
	if !m.Date.IsZero() {
		return m.Date.Format(time.RFC3339)
	}
	return strings.TrimSpace(m.DateRaw)
}

func mailboxes(lists []mailparse.AddressList) []mailparse.Mailbox {
	var out []mailparse.Mailbox
	for _, l := range lists {
		out = append(out, l.Mailboxes...)
	}
	return out
}

func mailboxStrings(lists []mailparse.AddressList) []string {
	var out []string
	for _, mb := range mailboxes(lists) {
		out = append(out, mb.String())
	}
	return out
}

func joinMailboxes(mbs []mailparse.Mailbox) string {
	s := make([]string, len(mbs))
	for i, mb := range mbs {
		s[i] = mb.String()
	}
	return strings.Join(s, ", ")
}

// returnPath writes the Return-Path mailboxes; a null reverse path (a bounce)
// is "<>".
func returnPath(lists []mailparse.AddressList) string {
	if mbs := mailboxes(lists); len(mbs) > 0 {
		return joinMailboxes(mbs)
	}
	for _, l := range lists {
		if l.Parsed {
			return "<>"
		}
	}
	return ""
}

func collapsedAll(h mailparse.Header, name string) []string {
	var out []string
	for _, f := range h.All(name) {
		out = append(out, f.Collapsed())
	}
	return out
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
