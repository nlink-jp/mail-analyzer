package analyzer

import (
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestAnalyzeOfflineEncodedNameSpoof(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/fixtures/08-rfc2047-address-spoof.eml")
	if err != nil {
		t.Fatal(err)
	}
	result := AnalyzeOffline(email)
	if !result.Indicators.Sender.DisplayNameSpoofing || !result.Judgment.IsSuspicious {
		t.Errorf("display-name spoofing not flagged: %+v", result.Judgment)
	}
}

func TestAnalyzeOfflineWinmailMacro(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/fixtures/winmail.eml")
	if err != nil {
		t.Fatal(err)
	}
	result := AnalyzeOffline(email)
	if result.Judgment.Category != "malware-delivery" {
		t.Errorf("Category = %q, want malware-delivery (the .docm inside winmail.dat)", result.Judgment.Category)
	}
}

func TestAnalyzeOfflineReportsParseWarnings(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/fixtures/10-malformed-header-line.eml")
	if err != nil {
		t.Fatal(err)
	}
	result := AnalyzeOffline(email)
	found := false
	for _, w := range result.ParseWarnings {
		if w.Code == "malformed_header_line" {
			found = true
		}
	}
	if !found {
		t.Errorf("ParseWarnings = %+v", result.ParseWarnings)
	}
}
