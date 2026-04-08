package parser

import (
	"io"
	"mime"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		enc, err := htmlindex.Get(charset)
		if err != nil {
			return input, nil
		}
		return transform.NewReader(input, enc.NewDecoder()), nil
	},
}

func decodeToUTF8(charset string, data []byte) string {
	if charset == "" {
		return string(data)
	}
	normalized := strings.ToLower(strings.TrimSpace(charset))
	if normalized == "utf-8" || normalized == "us-ascii" {
		return string(data)
	}

	enc, err := htmlindex.Get(charset)
	if err != nil {
		return string(data)
	}
	result, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err != nil {
		return string(data)
	}
	return string(result)
}

func decodeMIMEHeader(v string) string {
	if v == "" {
		return ""
	}
	decoded, err := wordDecoder.DecodeHeader(v)

	// Go's mime.WordDecoder sometimes returns the input unchanged with err=nil
	// when the encoded-word is malformed (e.g., spaces in Base64 payload).
	// Detect this by checking if encoded-word markers remain in the output.
	needsRetry := err != nil || strings.Contains(decoded, "=?")

	if needsRetry {
		fixed := fixBrokenEncodedWords(v)
		if fixed != v {
			if decoded2, err2 := wordDecoder.DecodeHeader(fixed); err2 == nil && !strings.Contains(decoded2, "=?") {
				return decoded2
			}
		}
		if err != nil {
			return v
		}
	}
	return decoded
}

// fixBrokenEncodedWords repairs RFC 2047 encoded-words that have spaces
// injected into the Base64 payload by broken MUAs or line-folding.
// e.g. "=?iso-2022-jp?B?abc def ghi?=" → "=?iso-2022-jp?B?abcdefghi?="
func fixBrokenEncodedWords(s string) string {
	// Pattern: =?charset?encoding?payload?=
	// We need to remove spaces within the payload portion.
	result := strings.Builder{}
	for len(s) > 0 {
		start := strings.Index(s, "=?")
		if start < 0 {
			result.WriteString(s)
			break
		}
		result.WriteString(s[:start])
		s = s[start:]

		// Find end of encoded-word
		end := strings.Index(s[2:], "?=")
		if end < 0 {
			result.WriteString(s)
			break
		}
		end += 4 // include "=?" prefix and "?=" suffix

		word := s[:end]
		// Split: =?charset?encoding?payload?=
		parts := strings.SplitN(word[2:end-2], "?", 3)
		if len(parts) == 3 {
			charset := parts[0]
			encoding := parts[1]
			payload := parts[2]
			// Remove spaces from payload
			payload = strings.ReplaceAll(payload, " ", "")
			payload = strings.ReplaceAll(payload, "\t", "")
			word = "=?" + charset + "?" + encoding + "?" + payload + "?="
		}

		result.WriteString(word)
		s = s[end:]
	}
	return result.String()
}

func decodeAddress(raw string) string {
	if raw == "" {
		return ""
	}
	decoded := decodeMIMEHeader(raw)
	// Clean up angle brackets for Return-Path etc.
	decoded = strings.TrimSpace(decoded)
	return decoded
}

func decodeAddressList(raw string) []string {
	if raw == "" {
		return nil
	}
	decoded := decodeMIMEHeader(raw)
	// Simple split on comma for robustness
	parts := strings.Split(decoded, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
