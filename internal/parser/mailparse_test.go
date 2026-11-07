package parser

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/mailparse"
	"github.com/nlink-jp/mailparse/msgtest"
)

func parse(t *testing.T, raw string) *Email {
	t.Helper()
	e, err := ParseBytes([]byte(strings.ReplaceAll(raw, "\n", "\r\n")), "t.eml")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func hasWarning(e *Email, code string) bool {
	for _, w := range e.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// An encoded display name that decodes to an address stays a name: the
// address is the one outside it, and the display string quotes the name.
func TestEncodedDisplayNameIsNotAnAddress(t *testing.T) {
	// "Bank <security@bank.example>" in RFC 2047 Base64.
	e := parse(t, "From: =?utf-8?b?QmFuayA8c2VjdXJpdHlAYmFuay5leGFtcGxlPg==?= <attacker@evil.example>\nTo: a@example.com\nSubject: s\nMessage-ID: <1@example.com>\n\nbody\n")
	if len(e.FromMailboxes) != 1 || e.FromMailboxes[0].Address != "attacker@evil.example" {
		t.Fatalf("FromMailboxes = %+v", e.FromMailboxes)
	}
	if e.From != `"Bank <security@bank.example>" <attacker@evil.example>` {
		t.Fatalf("From = %q", e.From)
	}
}

// Every From is kept, and a duplicate is warned about.
func TestDuplicateFromKept(t *testing.T) {
	e := parse(t, "From: a@example.com\nFrom: b@example.org\nTo: c@example.com\nSubject: s\nMessage-ID: <1@example.com>\n\nbody\n")
	if e.From != "a@example.com, b@example.org" || len(e.FromMailboxes) != 2 {
		t.Fatalf("From = %q", e.From)
	}
	if !hasWarning(e, mailparse.WarnDuplicateField) {
		t.Fatalf("warnings = %+v", e.Warnings)
	}
}

func TestHeaderFields(t *testing.T) {
	e := parse(t, "Return-Path: <>\nAuthentication-Results: forged.example; spf=pass\nAuthentication-Results: mx.example.com;\n spf=fail smtp.mailfrom=example.org\nReceived: from a.example.com\n by b.example.com; Mon, 2 Nov 2026 10:00:00 +0000\nX-Mailer: Tool 1\nFrom: a@example.com\nReply-To: b@example.org, c@example.net\nTo: d@example.com\nSubject: s\nDate: Mon, 2 Nov 2026 10:00:00 +0900\nMessage-ID: <1@example.com>\nIn-Reply-To: <0@example.com>\nReferences: <x@example.com> <0@example.com>\n\nbody\n")
	if e.ReturnPath != "<>" {
		t.Errorf("ReturnPath = %q", e.ReturnPath)
	}
	if len(e.AuthResults) != 2 || e.AuthResults[1] != "mx.example.com; spf=fail smtp.mailfrom=example.org" {
		t.Errorf("AuthResults = %q", e.AuthResults)
	}
	if len(e.Received) != 1 || e.Received[0] != "from a.example.com by b.example.com; Mon, 2 Nov 2026 10:00:00 +0000" {
		t.Errorf("Received = %q", e.Received)
	}
	if e.ReplyTo != "b@example.org, c@example.net" || len(e.ReplyToMailboxes) != 2 {
		t.Errorf("ReplyTo = %q", e.ReplyTo)
	}
	if e.XMailer != "Tool 1" || e.Date != "2026-11-02T10:00:00+09:00" || e.InReplyTo != "<0@example.com>" || e.References != "<x@example.com> <0@example.com>" {
		t.Errorf("%+v", e)
	}
}

// A forwarded message's body and attachments are searched and labelled by
// layer; a text/calendar attachment's text is searched too. The outer body
// alone is the Body.
func TestNestedAndTextAttachments(t *testing.T) {
	e := parse(t, `From: a@example.com
To: b@example.com
Subject: fwd
Message-ID: <1@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain

see attached
--b1
Content-Type: text/calendar; charset=utf-8; name="invite.ics"
Content-Disposition: attachment; filename="invite.ics"

URL:https://invite.example.net/join
--b1
Content-Type: message/rfc822

From: x@evil.example
To: b@example.com
Subject: inner
Message-ID: <2@evil.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b2"

--b2
Content-Type: text/plain

click https://inner.example.org/login
--b2
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="payload.exe"

MZ
--b2--
--b1--
`)
	if len(e.Body) != 1 || !strings.Contains(e.Body[0].Content, "see attached") {
		t.Fatalf("Body = %+v", e.Body)
	}
	var inner, invite bool
	for _, x := range e.Texts {
		if x.Layer != "" && strings.Contains(x.Content, "inner.example.org") {
			inner = true
		}
		if x.Layer == "" && x.Attachment == "invite.ics" && strings.Contains(x.Content, "invite.example.net") {
			invite = true
		}
	}
	if !inner || !invite {
		t.Fatalf("Texts = %+v", e.Texts)
	}
	var payload bool
	for _, a := range e.Attachments {
		if a.Filename == "payload.exe" && a.Layer != "" && a.Hash != "" {
			payload = true
		}
	}
	if !payload {
		t.Fatalf("Attachments = %+v", e.Attachments)
	}
}

// The format is recognized by content: a .msg named .eml is read as a .msg.
// The RTF copy of a body is left out of Body when another body exists.
func TestMSGByContent(t *testing.T) {
	sent := time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC)
	rtf := msgtest.CompressRTF([]byte(`{\rtf1\ansi\fromhtml1 {\*\htmltag <a href="https://rtf.example.com/">}x{\*\htmltag </a>}}`))
	b := msgtest.Message([]msgtest.Prop{
		msgtest.P(msgtest.PidTagSubject, "Hello"),
		msgtest.P(msgtest.PidTagSentRepresentingName, "Alice"),
		msgtest.P(msgtest.PidTagSentRepresentingSMTPAddress, "alice@example.com"),
		msgtest.P(msgtest.PidTagClientSubmitTime, sent),
		msgtest.P(msgtest.PidTagBody, msgtest.String8("plain")),
		msgtest.P(msgtest.PidTagRtfCompressed, rtf),
	},
		msgtest.Recipient(0, msgtest.P(msgtest.PidTagRecipientType, msgtest.RecipientTo), msgtest.P(msgtest.PidTagSMTPAddress, "bob@example.org")),
	)
	e, err := ParseBytes(b, "named.eml")
	if err != nil {
		t.Fatal(err)
	}
	if e.Subject != "Hello" || e.From != "Alice <alice@example.com>" || e.Date != "2026-11-07T01:02:03Z" || len(e.To) != 1 || e.To[0] != "bob@example.org" {
		t.Fatalf("%+v", e)
	}
	if len(e.Body) != 1 || e.Body[0].Content != "plain" || e.Body[0].Origin != "mapi" {
		t.Fatalf("Body = %+v", e.Body)
	}
}

// The RTF copy left out of Body is still searched for URLs.
func TestMSGRTFSearchedForURLs(t *testing.T) {
	rtf := msgtest.CompressRTF([]byte(`{\rtf1\ansi\fromhtml1 {\*\htmltag <a href="https://rtf-only.example.com/">}x{\*\htmltag </a>}}`))
	b := msgtest.Message([]msgtest.Prop{
		msgtest.P(msgtest.PidTagBody, msgtest.String8("plain")),
		msgtest.P(msgtest.PidTagRtfCompressed, rtf),
	})
	e, err := ParseBytes(b, "x.msg")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Body) != 1 || len(e.Texts) != 1 || e.Texts[0].Layer != "" || !strings.Contains(e.Texts[0].Content, "rtf-only.example.com") {
		t.Fatalf("Body %+v Texts %+v", e.Body, e.Texts)
	}
}

// A .msg whose only body is the compressed RTF shows that body.
func TestMSGRTFOnly(t *testing.T) {
	rtf := msgtest.CompressRTF([]byte(`{\rtf1\ansi\fromhtml1 {\*\htmltag <a href="https://rtf.example.com/">}x{\*\htmltag </a>}}`))
	b := msgtest.Message([]msgtest.Prop{
		msgtest.P(msgtest.PidTagSubject, "Hello"),
		msgtest.P(msgtest.PidTagRtfCompressed, rtf),
	})
	e, err := ParseBytes(b, "x.msg")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Body) != 1 || e.Body[0].Origin != "rtf" || !strings.Contains(e.HTMLBody(), "rtf.example.com") {
		t.Fatalf("Body = %+v", e.Body)
	}
}

func TestNotAMessage(t *testing.T) {
	if _, err := ParseBytes([]byte("data"), "test.txt"); !errors.Is(err, mailparse.ErrNotMessage) {
		t.Fatalf("err = %v", err)
	}
}

func TestTooLarge(t *testing.T) {
	big := make([]byte, mailparse.DefaultMaxSize+1)
	if _, err := ParseBytes(big, "big.eml"); !errors.Is(err, mailparse.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestEncodingIsFirstNonUTF8Charset(t *testing.T) {
	e := parse(t, "From: a@example.com\nTo: b@example.com\nSubject: s\nMessage-ID: <1@example.com>\nContent-Type: text/plain; charset=iso-2022-jp\n\nhello\n")
	if e.Encoding != "ISO-2022-JP" {
		t.Fatalf("Encoding = %q", e.Encoding)
	}
}

// A Unicode .msg body is stored as UTF-16LE; that is no charset to report.
func TestEncodingSkipsMSGUnicode(t *testing.T) {
	e, err := ParseBytes(msgtest.Message([]msgtest.Prop{msgtest.P(msgtest.PidTagBody, "unicode body")}), "x.msg")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Body) != 1 || e.Encoding != "" {
		t.Fatalf("Body %+v Encoding %q", e.Body, e.Encoding)
	}
}
