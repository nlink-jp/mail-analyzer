package llm

import (
	"errors"
	"strings"
	"testing"
)

func TestHintGemini3Location(t *testing.T) {
	notFound := errors.New("Error 404, Message: Publisher Model `projects/p/locations/us-central1/publishers/google/models/gemini-3.7-flash` was not found: NOT_FOUND")
	quota := errors.New("Error 429: RESOURCE_EXHAUSTED")

	tests := []struct {
		name     string
		err      error
		model    string
		location string
		wantHint bool
	}{
		{"gemini3 regional 404 gets hint", notFound, "gemini-3.7-flash", "us-central1", true},
		{"google/ prefix still recognized", notFound, "google/gemini-3.7-flash", "us-central1", true},
		{"gemini3 lite regional 404 gets hint", notFound, "gemini-3.5-flash-lite", "asia-northeast1", true},
		{"global location needs no hint", notFound, "gemini-3.7-flash", "global", false},
		{"gemini 2.5 model needs no hint", notFound, "gemini-2.5-flash", "us-central1", false},
		{"non-404 error passes through", quota, "gemini-3.7-flash", "us-central1", false},
		{"nil error stays nil", nil, "gemini-3.7-flash", "us-central1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hintGemini3Location(tt.err, tt.model, tt.location)
			if tt.err == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.err) {
				t.Errorf("wrapped error must preserve the original via errors.Is")
			}
			hasHint := strings.Contains(got.Error(), `set location = "global"`)
			if hasHint != tt.wantHint {
				t.Errorf("hint present = %v, want %v (err: %v)", hasHint, tt.wantHint, got)
			}
		})
	}
}
