package llm

import (
	"strings"
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/indicator"
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestBuildUserPromptShowsEveryFromField(t *testing.T) {
	email := &parser.Email{
		From: "ceo@example.org",
		FromFields: [][]parser.Mailbox{
			{{Address: "ceo@example.org"}},
			{{Name: "CEO", Address: "ceo@example.org"}, {Address: "attacker@phish.example"}},
		},
	}
	prompt := BuildUserPrompt(email, &indicator.Indicators{})
	if !strings.Contains(prompt, "From: ceo@example.org\nFrom: CEO <ceo@example.org>, attacker@phish.example\n") {
		t.Errorf("prompt should carry one From line per field:\n%s", prompt)
	}
}

func TestBuildUserPromptAuthPerHeaderAndWarnings(t *testing.T) {
	email := &parser.Email{
		From:     "a@example.com",
		Warnings: []parser.Warning{{Code: "duplicate_field"}, {Code: "duplicate_field"}, {Code: "malformed_header_line"}},
		Nested:   []*parser.Email{{Part: "2", Warnings: []parser.Warning{{Code: "invalid_base64", Part: "1"}}}},
	}
	ind := &indicator.Indicators{Authentication: indicator.AuthResult{
		SPF: "fail", DKIM: "pass", DMARC: "pass", Conflicting: true,
		PerHeader: []indicator.AuthVerdicts{{SPF: "pass", DKIM: "pass", DMARC: "pass"}, {SPF: "fail", DKIM: "none", DMARC: "none"}},
	}}
	prompt := BuildUserPrompt(email, ind)
	for _, want := range []string{
		"Authentication-Results headers (2, topmost first): [spf=pass dkim=pass dmarc=pass] [spf=fail dkim=none dmarc=none]",
		"they disagree",
		"Attached messages opened: 1",
		"Parse warnings: duplicate_field (x2), malformed_header_line, invalid_base64",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q:\n%s", want, prompt)
		}
	}
	// Indicators sit before the untrusted block.
	if strings.Index(prompt, "Parse warnings") > strings.Index(prompt, "<user-data-") {
		t.Error("parse warnings must be outside the untrusted data block")
	}
}
