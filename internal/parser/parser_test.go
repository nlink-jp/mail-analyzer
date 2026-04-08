package parser

import (
	"os"
	"testing"
)

func TestParseSimpleEML(t *testing.T) {
	email, err := ParseFile("../../testdata/simple.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if email.Subject != "Meeting Tomorrow" {
		t.Errorf("Subject = %q, want 'Meeting Tomorrow'", email.Subject)
	}
	if email.From != "sender@example.com" {
		t.Errorf("From = %q", email.From)
	}
	if len(email.To) != 1 || email.To[0] != "recipient@example.com" {
		t.Errorf("To = %v", email.To)
	}
	if email.Hash == "" {
		t.Error("Hash should not be empty")
	}
	if len(email.Hash) != 64 {
		t.Errorf("Hash length = %d, want 64 (SHA-256 hex)", len(email.Hash))
	}
	body := email.PlainTextBody()
	if body == "" {
		t.Error("PlainTextBody should not be empty")
	}
}

func TestParseSuspiciousEML(t *testing.T) {
	email, err := ParseFile("../../testdata/suspicious.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if email.Subject != "Urgent: Your Account Will Be Suspended" {
		t.Errorf("Subject = %q", email.Subject)
	}
	if email.ReturnPath != "<bounce@malicious-domain.com>" {
		t.Errorf("ReturnPath = %q", email.ReturnPath)
	}
	if email.AuthResults == "" {
		t.Error("AuthResults should not be empty")
	}
}

func TestParseAttachmentEML(t *testing.T) {
	email, err := ParseFile("../../testdata/attachment.eml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if len(email.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(email.Attachments))
	}

	att := email.Attachments[0]
	if att.Filename != "invoice.pdf" {
		t.Errorf("Filename = %q", att.Filename)
	}
	if att.Hash == "" {
		t.Error("Attachment hash should not be empty")
	}
	if att.Size == 0 {
		t.Error("Attachment size should not be 0")
	}
}

func TestParseUnsupportedExtension(t *testing.T) {
	_, err := ParseBytes([]byte("data"), "test.txt")
	if err == nil {
		t.Error("expected error for unsupported extension")
	}
}

func TestParseReaderAsEML(t *testing.T) {
	f, err := os.Open("../../testdata/simple.eml")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	email, err := ParseReader(f, "stdin")
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if email.Subject != "Meeting Tomorrow" {
		t.Errorf("Subject = %q", email.Subject)
	}
	if email.Source != "stdin" {
		t.Errorf("Source = %q, want 'stdin'", email.Source)
	}
}

func TestSHA256Consistency(t *testing.T) {
	data, err := os.ReadFile("../../testdata/simple.eml")
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256sum(data)
	h2 := sha256sum(data)
	if h1 != h2 {
		t.Error("SHA-256 should be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("SHA-256 hex length = %d, want 64", len(h1))
	}
}
