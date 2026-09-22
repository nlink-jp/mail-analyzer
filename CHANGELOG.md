# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).
- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

## [0.3.0] - 2026-08-28

### Changed

- **Default model is now `gemini-3.7-flash`** (was `gemini-2.5-flash`), ahead
  of the Vertex AI Gemini 2.5 retirement. Gemini 2.5 models still work when
  set explicitly via config or `MAIL_ANALYZER_MODEL`.
- **Default location is now `global`** (was `us-central1`): Vertex AI serves
  the Gemini 3 family only from the global endpoint — regional endpoints
  return 404 for them. Gemini 2.5 users should set a regional location
  explicitly.
- Updated google.golang.org/genai SDK.

### Added

- Actionable error hint: requesting a Gemini 3 model from a regional endpoint
  used to fail with a bare `404 NOT_FOUND`; the error now explains that
  Gemini 3 models require `location = "global"`.

## [0.2.0] - 2026-07-12

### Removed

- **darwin/amd64 (Intel) pre-built binary.** macOS releases now ship
  **arm64 only**, per the org-wide policy (darwin is Apple-Silicon only; no
  universal binaries). Intel Mac users can build from source.

### Changed

- **Linux release archives are now `.tar.gz`** (darwin/windows remain `.zip`),
  per `nlink-jp/.github` CONVENTIONS.md §Release Archive Standard. Archives
  still bundle `LICENSE` + `README.md` alongside the canonical binary.
- **darwin code-signature identifier** is now the canonical `mail-analyzer`
  (was `mail-analyzer-darwin-arm64`), set via `codesign -i` so it stays
  stable after the archived binary is renamed to its canonical name.

No change to the binary's behaviour — a packaging / build-config release.

## [0.1.2] - 2026-05-23

### Added

- **`package` Makefile target.** Builds all 5 platforms, signs darwin
  binaries with Developer ID, zips each with LICENSE + README.md
  using versioned naming
  (`mail-analyzer-vX.Y.Z-<os>-<arch>.zip`), and notarizes the
  darwin zips. Replaces the previous manual zip step that produced
  the v0.1.1 release.

### Changed

- **Darwin releases are now Developer ID signed and Apple-notarized.**
  `mail-analyzer-v0.1.2-darwin-{amd64,arm64}.zip` carry full Apple
  Developer ID Application signatures and notarization tickets from
  Apple. End users on macOS no longer need to bypass Gatekeeper
  with right-click → Open or `xattr -d com.apple.quarantine` on
  first launch; local users who place `mail-analyzer` under
  Dropbox-synced (or any other FileProvider-managed) paths are no
  longer killed by macOS's ad-hoc + provenance distrust policy.
  Pipeline: `scripts/codesign-darwin.sh` +
  `scripts/notarize-darwin.sh`, driven by `make package`. Adopts
  the org-wide convention in `nlink-jp/.github` CONVENTIONS.md
  §Code Signing.

No behaviour change to the binary itself — feature-wise this is
identical to v0.1.1.

## [0.1.1] - 2026-04-14

### Added

- TOML config file support (`~/.config/mail-analyzer/config.toml`)
- `--config` flag to override config file path
- `GOOGLE_CLOUD_PROJECT` / `GOOGLE_CLOUD_LOCATION` env var fallback

## [0.1.0] - 2026-04-09

### Added

- EML parser with full charset support (adapted from eml-to-jsonl)
- MSG parser with OLE2/MAPI support (adapted from msg-to-jsonl)
- SHA-256 hashing for email files and individual attachments
- Authentication indicator: SPF/DKIM/DMARC result parsing
- Sender indicator: From/Return-Path mismatch, display name spoofing, Reply-To divergence
- URL indicator: extraction, deduplication, defanging, classification (free hosting, shortener, suspicious TLD, Azure Blob)
- Attachment indicator: dangerous extensions, macro-enabled Office, double extension detection
- Routing indicator: X-Mailer classification, suspicious Received header detection (localhost, local domains, IP-only HELO)
- Gemini LLM analysis via google.golang.org/genai SDK (Vertex AI)
- Prompt injection defense with nonce-tagged XML boundaries (defense at prompt top)
- Structured JSON output with composite judgment (is_suspicious, category, confidence, reasons, tags)
- Offline mode (--offline) for rule-based analysis without LLM
- Exponential backoff with jitter for LLM API retries
- SPF/DMARC failure handling: not flagged alone (reduces false positives from forwarded emails)
- Subdomain-aware sender comparison (bounce.mag.subaru.jp matches mag.subaru.jp)
- Broken RFC 2047 encoded-word repair (spaces in Base64 payload from line folding)
- Schema/namespace URL filtering (Microsoft Office XML schemas excluded from analysis)
