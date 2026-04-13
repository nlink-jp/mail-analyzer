package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"time"

	"google.golang.org/genai"

	"github.com/nlink-jp/mail-analyzer/internal/config"
)

const (
	maxRetries = 5
	baseDelay  = 5.0
	maxDelay   = 120.0
	jitter     = 1.0
)

// Judgment is the structured LLM analysis result.
type Judgment struct {
	IsSuspicious bool     `json:"is_suspicious"`
	Category     string   `json:"category"`
	Confidence   float64  `json:"confidence"`
	Summary      string   `json:"summary"`
	Reasons      []string `json:"reasons"`
	Tags         []string `json:"tags"`
}

// Analyze sends the email data to Gemini and returns a structured judgment.
func Analyze(ctx context.Context, cfg *config.Config, systemPrompt, userPrompt string) (*Judgment, error) {
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		Project:  cfg.GCP.Project,
		Location: cfg.GCP.Location,
		Backend:  genai.BackendVertexAI,
	})
	if err != nil {
		return nil, fmt.Errorf("creating Gemini client: %w", err)
	}

	temp := float32(0.2)
	gcfg := &genai.GenerateContentConfig{
		SystemInstruction: genai.NewContentFromText(systemPrompt, genai.RoleUser),
		Temperature:       &temp,
		ResponseMIMEType:  "application/json",
	}

	var lastErr error
	for attempt := range maxRetries + 1 {
		resp, err := client.Models.GenerateContent(ctx, cfg.Model.Name, genai.Text(userPrompt), gcfg)
		if err == nil && resp != nil {
			text := extractText(resp)
			if text == "" {
				return nil, fmt.Errorf("empty response from LLM")
			}

			judgment, parseErr := parseJudgment(text)
			if parseErr != nil {
				return nil, fmt.Errorf("parsing LLM response: %w", parseErr)
			}
			return judgment, nil
		}

		if err != nil {
			lastErr = err
			errStr := strings.ToLower(err.Error())
			isRetryable := false
			for _, k := range []string{"429", "resource_exhausted", "503", "500", "unavailable", "deadline"} {
				if strings.Contains(errStr, k) {
					isRetryable = true
					break
				}
			}

			if !isRetryable || attempt == maxRetries {
				return nil, fmt.Errorf("LLM analysis failed: %w", err)
			}

			delay := min(baseDelay*float64(int(1)<<attempt), maxDelay)
			delay += rand.Float64()*2*jitter - jitter
			if delay < 0 {
				delay = 0
			}
			log.Printf("LLM call failed (attempt %d/%d), retrying in %.1fs: %v", attempt+1, maxRetries+1, delay, err)
			time.Sleep(time.Duration(delay * float64(time.Second)))
		}
	}

	return nil, fmt.Errorf("LLM analysis failed after %d retries: %w", maxRetries, lastErr)
}

func extractText(resp *genai.GenerateContentResponse) string {
	if resp == nil {
		return ""
	}
	for _, c := range resp.Candidates {
		if c.Content != nil {
			for _, p := range c.Content.Parts {
				if p.Text != "" {
					return p.Text
				}
			}
		}
	}
	return ""
}

func parseJudgment(text string) (*Judgment, error) {
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```") {
		lines := strings.Split(cleaned, "\n")
		var filtered []string
		for _, l := range lines[1:] {
			if !strings.HasPrefix(strings.TrimSpace(l), "```") {
				filtered = append(filtered, l)
			}
		}
		cleaned = strings.Join(filtered, "\n")
	}

	var j Judgment
	if err := json.Unmarshal([]byte(cleaned), &j); err != nil {
		return nil, err
	}

	validCategories := map[string]bool{
		"phishing": true, "spam": true, "malware-delivery": true,
		"bec": true, "scam": true, "safe": true,
	}
	if !validCategories[j.Category] {
		j.Category = "safe"
	}

	if len(j.Tags) > 5 {
		j.Tags = j.Tags[:5]
	}
	if len(j.Reasons) > 5 {
		j.Reasons = j.Reasons[:5]
	}

	if j.Confidence < 0 {
		j.Confidence = 0
	}
	if j.Confidence > 1 {
		j.Confidence = 1
	}

	return &j, nil
}
