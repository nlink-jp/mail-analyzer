package analyzer

import (
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestAnalyzeOfflineSafe(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/simple.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	if result.Judgment.IsSuspicious {
		t.Error("simple email should not be suspicious")
	}
	if result.Judgment.Category != "safe" {
		t.Errorf("Category = %q, want 'safe'", result.Judgment.Category)
	}
	if result.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

func TestAnalyzeOfflineSuspicious(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/suspicious.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	if !result.Judgment.IsSuspicious {
		t.Error("suspicious email should be detected")
	}
	if len(result.Judgment.Reasons) == 0 {
		t.Error("should have at least one reason")
	}
	if result.Indicators == nil {
		t.Error("Indicators should not be nil")
	}
	if result.Indicators.Authentication.SPF != "fail" {
		t.Errorf("SPF = %q, want 'fail'", result.Indicators.Authentication.SPF)
	}
}

func TestAnalyzeOfflineWithAttachment(t *testing.T) {
	email, err := parser.ParseFile("../../testdata/attachment.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	result := AnalyzeOffline(email)

	// Clean PDF attachment should not be suspicious
	if result.Judgment.IsSuspicious {
		t.Error("email with clean PDF should not be suspicious")
	}
}
