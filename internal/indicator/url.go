package indicator

import (
	"regexp"
	"strings"

	"github.com/nlink-jp/mail-analyzer/internal/parser"
)

// URLResult holds analysis of a single URL found in the email.
type URLResult struct {
	URL        string `json:"url"`
	Suspicious bool   `json:"suspicious"`
	Reason     string `json:"reason,omitempty"`
}

var (
	urlRegex  = regexp.MustCompile(`https?://[^\s"<>]*[^\s"<>,.?!;)]`)
	hrefRegex = regexp.MustCompile(`href\s*=\s*["']([^"']+)["']`)
)

// Free hosting / cloud storage domains commonly abused for phishing.
// Matched as suffix (e.g. "evil.web.core.windows.net" matches "web.core.windows.net").
var freeHostingSuffixes = []string{
	// Cloud storage / static hosting
	"web.core.windows.net",  // Azure Blob Storage static website
	"blob.core.windows.net", // Azure Blob Storage direct
	"azurewebsites.net",     // Azure App Service
	"cloudfront.net",        // AWS CloudFront (often abused)
	"s3.amazonaws.com",      // AWS S3
	"storage.googleapis.com",
	"firebaseapp.com",
	"web.app",

	// Website builders
	"000webhostapp.com",
	"blogspot.com",
	"weebly.com",
	"wixsite.com",
	"wordpress.com",
	"sites.google.com",
	"github.io",
	"netlify.app",
	"vercel.app",
	"herokuapp.com",
	"pages.dev", // Cloudflare Pages
	"workers.dev",
}

var shortenerDomains = map[string]bool{
	"bit.ly": true, "t.co": true, "tinyurl.com": true, "goo.gl": true,
	"ow.ly": true, "is.gd": true, "buff.ly": true, "rebrand.ly": true,
	"cutt.ly": true, "shorturl.at": true,
}

// Suspicious TLDs commonly used in phishing/scam campaigns.
var suspiciousTLDs = map[string]bool{
	".cfd": true, ".top": true, ".xyz": true, ".click": true,
	".buzz": true, ".gdn": true, ".icu": true, ".club": true,
	".online": true, ".site": true, ".store": true, ".fun": true,
	".rest": true, ".monster": true, ".sbs": true, ".cyou": true,
}

func analyzeURLs(email *parser.Email) []URLResult {
	seen := map[string]bool{}
	var results []URLResult

	for _, bp := range email.Body {
		urls := extractURLs(bp.Content)
		for _, u := range urls {
			if seen[u] {
				continue
			}
			seen[u] = true

			// Skip non-HTTP URLs and schema references
			if isSchemaOrStyleURL(u) {
				continue
			}

			result := URLResult{URL: defangURL(u)}
			domain := extractURLDomain(u)

			switch {
			case matchesSuffix(domain, freeHostingSuffixes):
				result.Suspicious = true
				result.Reason = "free hosting / cloud storage service"
			case shortenerDomains[domain]:
				result.Suspicious = true
				result.Reason = "URL shortener"
			case hasSuspiciousTLD(domain):
				result.Suspicious = true
				result.Reason = "suspicious TLD"
			case strings.Contains(u, "@"):
				result.Suspicious = true
				result.Reason = "URL contains @ (potential redirect)"
			}

			results = append(results, result)
		}
	}

	return results
}

// isSchemaOrStyleURL returns true for XML schema / namespace URIs
// that appear in HTML emails but are not clickable links.
func isSchemaOrStyleURL(u string) bool {
	return strings.Contains(u, "schemas.microsoft.com") ||
		strings.Contains(u, "schemas.openxmlformats.org") ||
		strings.Contains(u, "www.w3.org/") ||
		strings.Contains(u, "purl.org/")
}

// matchesSuffix checks if domain ends with any of the given suffixes.
// Handles subdomain matching (e.g., "evil.web.core.windows.net" matches "web.core.windows.net").
func matchesSuffix(domain string, suffixes []string) bool {
	for _, s := range suffixes {
		if domain == s || strings.HasSuffix(domain, "."+s) {
			return true
		}
	}
	return false
}

// hasSuspiciousTLD checks if the domain uses a TLD commonly abused in phishing.
func hasSuspiciousTLD(domain string) bool {
	lastDot := strings.LastIndex(domain, ".")
	if lastDot < 0 {
		return false
	}
	tld := domain[lastDot:]
	return suspiciousTLDs[tld]
}

func extractURLs(text string) []string {
	seen := map[string]bool{}
	var urls []string

	for _, m := range hrefRegex.FindAllStringSubmatch(text, -1) {
		u := strings.TrimSpace(m[1])
		if !seen[u] && (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	for _, u := range urlRegex.FindAllString(text, -1) {
		u = strings.TrimSpace(u)
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	return urls
}

func defangURL(u string) string {
	u = strings.Replace(u, "http://", "hxxp://", 1)
	u = strings.Replace(u, "https://", "hxxps://", 1)
	parts := strings.SplitN(u, "//", 2)
	if len(parts) == 2 {
		slashIdx := strings.Index(parts[1], "/")
		if slashIdx < 0 {
			parts[1] = strings.ReplaceAll(parts[1], ".", "[.]")
		} else {
			domain := parts[1][:slashIdx]
			rest := parts[1][slashIdx:]
			parts[1] = strings.ReplaceAll(domain, ".", "[.]") + rest
		}
		return parts[0] + "//" + parts[1]
	}
	return u
}

func extractURLDomain(u string) string {
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	return strings.ToLower(u)
}
