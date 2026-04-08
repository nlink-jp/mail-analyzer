package llm

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nlink-jp/mail-analyzer/internal/indicator"
	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

func TestBuildSystemPrompt(t *testing.T) {
	prompt := BuildSystemPrompt("")
	if !strings.Contains(prompt, "phishing") {
		t.Error("system prompt should contain category 'phishing'")
	}
	if !strings.Contains(prompt, "OPAQUE DATA") {
		t.Error("system prompt should contain injection defense instruction")
	}
	if !strings.Contains(prompt, "Defang") {
		t.Error("system prompt should contain defang instruction")
	}
}

func TestBuildSystemPromptWithLang(t *testing.T) {
	prompt := BuildSystemPrompt("ja")
	if !strings.Contains(prompt, "ja") {
		t.Error("system prompt should contain language instruction")
	}
}

func TestBuildUserPrompt(t *testing.T) {
	email := &parser.Email{
		Subject: "Test Subject",
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Date:    "2026-03-31",
		Body:    []parser.BodyPart{{Type: "text/plain", Content: "Test body"}},
	}
	indicators := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "pass", DKIM: "pass", DMARC: "pass"},
	}

	prompt := BuildUserPrompt(email, indicators)

	if !strings.Contains(prompt, "Test Subject") {
		t.Error("user prompt should contain subject")
	}
	if !strings.Contains(prompt, "sender@example.com") {
		t.Error("user prompt should contain sender")
	}
	if !strings.Contains(prompt, "<user-data-") {
		t.Error("user prompt should contain nonce-tagged boundary")
	}

	// Nonce should be unique each call
	prompt2 := BuildUserPrompt(email, indicators)
	nonces1 := regexp.MustCompile(`user-data-([a-f0-9]+)`).FindStringSubmatch(prompt)
	nonces2 := regexp.MustCompile(`user-data-([a-f0-9]+)`).FindStringSubmatch(prompt2)
	if nonces1[1] == nonces2[1] {
		t.Error("nonce should be unique per call")
	}
}

func TestBuildUserPromptTruncation(t *testing.T) {
	longBody := strings.Repeat("x", 5000)
	email := &parser.Email{
		Body: []parser.BodyPart{{Type: "text/plain", Content: longBody}},
	}
	indicators := &indicator.Indicators{
		Authentication: indicator.AuthResult{SPF: "none", DKIM: "none", DMARC: "none"},
	}

	prompt := BuildUserPrompt(email, indicators)
	if strings.Contains(prompt, strings.Repeat("x", 5000)) {
		t.Error("body should be truncated in prompt")
	}
}

func TestParseJudgment(t *testing.T) {
	json := `{"is_suspicious":true,"category":"phishing","confidence":0.95,"summary":"test","reasons":["SPF fail"],"tags":["phishing"]}`
	j, err := parseJudgment(json)
	if err != nil {
		t.Fatalf("parseJudgment: %v", err)
	}
	if !j.IsSuspicious {
		t.Error("IsSuspicious should be true")
	}
	if j.Category != "phishing" {
		t.Errorf("Category = %q", j.Category)
	}
	if j.Confidence != 0.95 {
		t.Errorf("Confidence = %f", j.Confidence)
	}
}

func TestParseJudgmentInvalidCategory(t *testing.T) {
	json := `{"is_suspicious":false,"category":"unknown","confidence":0.5,"summary":"test","reasons":[],"tags":[]}`
	j, err := parseJudgment(json)
	if err != nil {
		t.Fatalf("parseJudgment: %v", err)
	}
	if j.Category != "safe" {
		t.Errorf("invalid category should default to 'safe', got %q", j.Category)
	}
}

func TestParseJudgmentMarkdownFence(t *testing.T) {
	raw := "```json\n{\"is_suspicious\":false,\"category\":\"safe\",\"confidence\":0.1,\"summary\":\"ok\",\"reasons\":[],\"tags\":[]}\n```"
	j, err := parseJudgment(raw)
	if err != nil {
		t.Fatalf("parseJudgment with fences: %v", err)
	}
	if j.Category != "safe" {
		t.Errorf("Category = %q", j.Category)
	}
}

func TestParseJudgmentConfidenceClamp(t *testing.T) {
	json := `{"is_suspicious":true,"category":"phishing","confidence":1.5,"summary":"test","reasons":[],"tags":[]}`
	j, err := parseJudgment(json)
	if err != nil {
		t.Fatal(err)
	}
	if j.Confidence != 1.0 {
		t.Errorf("Confidence should be clamped to 1.0, got %f", j.Confidence)
	}
}
