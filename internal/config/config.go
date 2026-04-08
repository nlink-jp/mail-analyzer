// Package config provides configuration for mail-analyzer.
package config

import (
	"fmt"
	"os"
)

// Config holds runtime configuration.
type Config struct {
	Project  string // GCP project ID
	Location string // Vertex AI location
	Model    string // Gemini model name
	Lang     string // Force summary language (optional)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	c := &Config{
		Project:  os.Getenv("MAIL_ANALYZER_PROJECT"),
		Location: envOrDefault("MAIL_ANALYZER_LOCATION", "us-central1"),
		Model:    envOrDefault("MAIL_ANALYZER_MODEL", "gemini-2.5-flash"),
		Lang:     os.Getenv("MAIL_ANALYZER_LANG"),
	}

	if c.Project == "" {
		return nil, fmt.Errorf("MAIL_ANALYZER_PROJECT is required")
	}

	return c, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
