// Package config provides configuration for mail-analyzer.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds runtime configuration.
type Config struct {
	GCP   GCPConfig   `toml:"gcp"`
	Model ModelConfig `toml:"model"`
	Lang  string      `toml:"lang"`
}

// GCPConfig holds Google Cloud settings.
type GCPConfig struct {
	Project  string `toml:"project"`
	Location string `toml:"location"`
}

// ModelConfig holds model settings.
type ModelConfig struct {
	Name string `toml:"name"`
}

// Project returns the GCP project ID.
func (c *Config) Project() string { return c.GCP.Project }

// Location returns the Vertex AI location.
func (c *Config) Location() string { return c.GCP.Location }

// ModelName returns the Gemini model name.
func (c *Config) ModelName() string { return c.Model.Name }

// Load reads config from the given path, with env var overrides.
// If path is empty, tries the default location (~/.config/mail-analyzer/config.toml).
func Load(path string) (*Config, error) {
	cfg := &Config{
		GCP: GCPConfig{
			Location: "us-central1",
		},
		Model: ModelConfig{
			Name: "gemini-2.5-flash",
		},
	}

	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, ".config", "mail-analyzer", "config.toml")
		}
	}

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if _, err := toml.DecodeFile(path, cfg); err != nil {
				return nil, fmt.Errorf("parse config %s: %w", path, err)
			}
		}
	}

	// Env overrides (tool-specific > generic)
	if v := os.Getenv("MAIL_ANALYZER_PROJECT"); v != "" {
		cfg.GCP.Project = v
	} else if v := os.Getenv("GOOGLE_CLOUD_PROJECT"); v != "" {
		cfg.GCP.Project = v
	}
	if v := os.Getenv("MAIL_ANALYZER_LOCATION"); v != "" {
		cfg.GCP.Location = v
	} else if v := os.Getenv("GOOGLE_CLOUD_LOCATION"); v != "" {
		cfg.GCP.Location = v
	}
	if v := os.Getenv("MAIL_ANALYZER_MODEL"); v != "" {
		cfg.Model.Name = v
	}
	if v := os.Getenv("MAIL_ANALYZER_LANG"); v != "" {
		cfg.Lang = v
	}

	if cfg.GCP.Project == "" {
		return nil, fmt.Errorf("GCP project is required: set gcp.project in config, MAIL_ANALYZER_PROJECT, or GOOGLE_CLOUD_PROJECT env var")
	}

	return cfg, nil
}
