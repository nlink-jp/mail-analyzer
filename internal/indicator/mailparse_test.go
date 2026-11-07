package indicator

import (
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestAnalyzeAuthAllSeesFailBehindForgedPass(t *testing.T) {
	got := analyzeAuthAll([]string{
		"mx.example.org; spf=pass smtp.mailfrom=sender.example.net; dkim=pass; dmarc=pass",
		"mx.example.org; spf=fail smtp.mailfrom=forged.example",
	})
	if got.SPF != "fail" || got.DKIM != "pass" || got.DMARC != "pass" {
		t.Errorf("verdicts = %s/%s/%s, want fail/pass/pass", got.SPF, got.DKIM, got.DMARC)
	}
	if !got.Conflicting {
		t.Error("Conflicting should be true")
	}
	if len(got.PerHeader) != 2 || got.PerHeader[0].SPF != "pass" || got.PerHeader[1].SPF != "fail" {
		t.Errorf("PerHeader = %+v", got.PerHeader)
	}
}

func TestAnalyzeAuthAllOrderDoesNotMatter(t *testing.T) {
	a := analyzeAuthAll([]string{"x; dmarc=fail", "x; dmarc=pass"})
	b := analyzeAuthAll([]string{"x; dmarc=pass", "x; dmarc=fail"})
	if a.DMARC != "fail" || b.DMARC != "fail" {
		t.Errorf("DMARC = %s / %s, want fail both ways", a.DMARC, b.DMARC)
	}
}

func TestAnalyzeAuthAllSingleAndAbsent(t *testing.T) {
	one := analyzeAuthAll([]string{"x; spf=softfail dkim=pass"})
	if one.SPF != "softfail" || one.DKIM != "pass" || one.DMARC != "none" {
		t.Errorf("single = %+v", one)
	}
	if one.PerHeader != nil || one.Conflicting {
		t.Errorf("a single header needs no per-header detail: %+v", one)
	}
	// A field without a method neither wins nor conflicts.
	two := analyzeAuthAll([]string{"x; spf=pass", "y; dkim=pass"})
	if two.Conflicting || two.SPF != "pass" || two.DKIM != "pass" {
		t.Errorf("disjoint methods = %+v", two)
	}
	if got := analyzeAuthAll(nil); got.SPF != "none" || got.Conflicting {
		t.Errorf("no headers = %+v", got)
	}
}

func TestAnalyzeSenderReadsEveryFromMailbox(t *testing.T) {
	email := &parser.Email{
		From: "ceo@example.org",
		FromFields: [][]parser.Mailbox{
			{{Address: "ceo@example.org"}},
			{{Name: "CEO", Address: "ceo@example.org"}, {Address: "attacker@phish.example"}},
		},
		ReturnPaths: []string{"bounce@example.org"},
	}
	got := analyzeSender(email)
	if !got.FromReturnPathMismatch {
		t.Error("a second From mailbox in another domain should mismatch the Return-Path")
	}
}

func TestAnalyzeSenderEncodedNameSpoofing(t *testing.T) {
	// What fixture 08 parses to: the decoded name holds an address.
	email := &parser.Email{
		From: `"Bank Security <security@bank.example>" <attacker@phish.example>`,
		FromFields: [][]parser.Mailbox{
			{{Name: "Bank Security <security@bank.example>", Address: "attacker@phish.example"}},
		},
	}
	if !analyzeSender(email).DisplayNameSpoofing {
		t.Error("a display name holding an address should be flagged")
	}
}

func TestAnalyzeSenderReplyToMailboxes(t *testing.T) {
	email := &parser.Email{
		FromFields:       [][]parser.Mailbox{{{Address: "info@example.com"}}},
		ReplyToMailboxes: []parser.Mailbox{{Address: "info@example.com"}, {Address: "x@evil.example"}},
	}
	if !analyzeSender(email).ReplyToDivergence {
		t.Error("any Reply-To mailbox outside the From domains should diverge")
	}
}

func TestNestedURLsAndAttachments(t *testing.T) {
	email := &parser.Email{
		Body: []parser.BodyPart{{Type: "text/plain", Content: "see attached"}},
		Attachments: []parser.Attachment{
			{Filename: "original.eml", MIMEType: "message/rfc822", Size: 10, Hash: "h"},
		},
		Nested: []*parser.Email{{
			Part:        "2",
			Body:        []parser.BodyPart{{Type: "text/html", Content: `<a href="https://bit.ly/x">x</a>`}},
			Attachments: []parser.Attachment{{Filename: "run.exe", Size: 1, Hash: "h2"}},
		}},
	}
	urls := analyzeURLs(email)
	if len(urls) != 1 || !urls[0].Suspicious || urls[0].InMessage != "2" {
		t.Errorf("URLs = %+v", urls)
	}
	atts := analyzeAttachments(email)
	if len(atts) != 2 {
		t.Fatalf("attachments = %+v", atts)
	}
	if atts[0].InMessage != "" || atts[1].InMessage != "2" || !atts[1].Suspicious {
		t.Errorf("attachments = %+v", atts)
	}
}

func TestFixtureDuplicateHeaders(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/fixtures/07-duplicate-headers.eml")
	if err != nil {
		t.Fatal(err)
	}
	got := Analyze(email)
	if got.Authentication.SPF != "fail" {
		t.Errorf("SPF = %q, want the fail under the forged pass", got.Authentication.SPF)
	}
}
