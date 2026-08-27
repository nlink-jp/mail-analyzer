package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearEnv blanks every env var Load consults, so tests are immune to the
// developer's real environment. t.Setenv also restores originals on cleanup.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"MAIL_ANALYZER_PROJECT", "GOOGLE_CLOUD_PROJECT",
		"MAIL_ANALYZER_LOCATION", "GOOGLE_CLOUD_LOCATION",
		"MAIL_ANALYZER_MODEL", "MAIL_ANALYZER_LANG",
	} {
		t.Setenv(k, "")
	}
}

// missingPath returns a path that does not exist, so Load falls through to
// built-in defaults without touching the developer's real config file.
func missingPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-such-config.toml")
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("MAIL_ANALYZER_PROJECT", "test-project")

	cfg, err := Load(missingPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Location(); got != "global" {
		t.Errorf("default location = %q, want %q (Gemini 3 models are global-endpoint only)", got, "global")
	}
	if got := cfg.ModelName(); !strings.HasPrefix(got, "gemini-3") {
		t.Errorf("default model = %q, want a Gemini 3 model", got)
	}
}

func TestLoadTOMLFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	toml := `[gcp]
project  = "file-project"
location = "us-central1"

[model]
name = "gemini-2.5-flash"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project() != "file-project" {
		t.Errorf("project = %q, want file-project", cfg.Project())
	}
	if cfg.Location() != "us-central1" {
		t.Errorf("location = %q, want us-central1 (file must override the global default)", cfg.Location())
	}
	if cfg.ModelName() != "gemini-2.5-flash" {
		t.Errorf("model = %q, want gemini-2.5-flash", cfg.ModelName())
	}
}

func TestEnvOverridesFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	toml := `[gcp]
project  = "file-project"
location = "us-central1"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GOOGLE_CLOUD_PROJECT", "generic-project")
	t.Setenv("MAIL_ANALYZER_PROJECT", "tool-project")
	t.Setenv("MAIL_ANALYZER_LOCATION", "global")
	t.Setenv("MAIL_ANALYZER_MODEL", "gemini-3.7-flash")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project() != "tool-project" {
		t.Errorf("project = %q, want tool-project (tool-specific env beats generic and file)", cfg.Project())
	}
	if cfg.Location() != "global" {
		t.Errorf("location = %q, want global (env beats file)", cfg.Location())
	}
	if cfg.ModelName() != "gemini-3.7-flash" {
		t.Errorf("model = %q, want gemini-3.7-flash", cfg.ModelName())
	}
}

func TestMissingProjectFails(t *testing.T) {
	clearEnv(t)

	if _, err := Load(missingPath(t)); err == nil {
		t.Fatal("Load succeeded without a GCP project; want an error")
	}
}
