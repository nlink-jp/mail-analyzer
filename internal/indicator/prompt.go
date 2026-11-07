package indicator

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The LLM prompt helpers below live here, not in package llm, so that both
// mail-analyzer and mail-analyzer-local describe the indicators the same way.

// Limits on the Authentication-Results passed to the LLM.
const (
	PromptAuthFields   = 10
	PromptAuthFieldLen = 300
)

// Where says where a URL was found, for the LLM: "" for the outer body.
func (u URLResult) Where() string { return where(u.Layer, u.Attachment) }

// Where says where an attachment was found, for the LLM: "" for the outer message.
func (a AttachResult) Where() string { return where(a.Layer, "") }

func where(layer, attachment string) string {
	var parts []string
	if layer != "" {
		parts = append(parts, "in attached message "+layer)
	}
	if attachment != "" {
		parts = append(parts, fmt.Sprintf("in text attachment %q", attachment))
	}
	return strings.Join(parts, ", ")
}

// PromptAuthResults returns the Authentication-Results fields to show the
// LLM: at most PromptAuthFields, each cut to PromptAuthFieldLen characters.
// They are attacker-influenced text and belong inside the untrusted-data tags.
func PromptAuthResults(raw []string) []string {
	var out []string
	for i, f := range raw {
		if i == PromptAuthFields {
			out = append(out, fmt.Sprintf("(%d more not shown)", len(raw)-i))
			break
		}
		if utf8.RuneCountInString(f) > PromptAuthFieldLen {
			f = string([]rune(f)[:PromptAuthFieldLen]) + "..."
		}
		out = append(out, f)
	}
	return out
}
