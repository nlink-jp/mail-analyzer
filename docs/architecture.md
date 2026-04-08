# Architecture — mail-analyzer

This document describes the design decisions, analysis methodology, and
rationale behind mail-analyzer. It serves as a reference for developers,
security reviewers, and operators.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Analysis Pipeline](#analysis-pipeline)
3. [Parser Design](#parser-design)
4. [Indicator Engine](#indicator-engine)
5. [LLM Analysis](#llm-analysis)
6. [Composite Judgment](#composite-judgment)
7. [Design Decisions and Rationale](#design-decisions-and-rationale)

---

## Design Philosophy

mail-analyzer follows three core principles:

1. **Defense in depth**: Rule-based indicators catch known patterns with zero
   false negatives; LLM catches novel patterns that rules miss. Neither layer
   alone is sufficient.

2. **Deterministic first, probabilistic second**: Indicators produce
   reproducible, explainable results. LLM adds nuance but its output is
   always validated and constrained.

3. **Fail open for analysis, fail closed for classification**: If parsing
   succeeds but LLM fails, the tool still outputs indicator results. If
   parsing fails, the tool exits with an error (no partial results).

---

## Analysis Pipeline

```
Input (.eml / .msg)
    │
    ▼
┌──────────────┐
│ Parser       │  SHA-256 hash of file
│              │  Header extraction (Subject, From, To, Return-Path,
│              │    Reply-To, Authentication-Results, Received, X-Mailer)
│              │  Body extraction (text/plain, text/html, charset conversion)
│              │  Attachment extraction (metadata + SHA-256 hash per attachment)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Indicators   │  Rule-based, deterministic
│              │
│  auth.go     │  SPF / DKIM / DMARC verdict parsing
│  sender.go   │  From↔Return-Path, Display Name spoofing, Reply-To
│  url.go      │  URL extraction, defanging, classification
│  attachment.go│  Extension risk, macro detection, double extension
│  routing.go  │  X-Mailer classification, Received header analysis
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ LLM          │  Gemini (Vertex AI) content analysis
│              │  Nonce-tagged prompt injection defense
│              │  Structured JSON output (response_mime_type)
│              │  Retry with exponential backoff + jitter
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Composite    │  Merge indicators + LLM → final judgment
│ Judgment     │  is_suspicious, category, confidence, reasons, tags
└──────────────┘
       │
       ▼
    stdout (JSON)
```

---

## Parser Design

### Why internal parsers (not external tools)?

The original mail-analyzer depended on `eml-to-jsonl` and `msg-to-jsonl` as
external CLI tools. This created deployment complexity and version coupling.
v2 internalizes the parsers for:

- **Single binary distribution**: no external dependencies at runtime
- **Attachment binary access**: external tools output metadata only; we need
  raw bytes to compute SHA-256 hashes
- **Header access**: we need Return-Path, Reply-To, Authentication-Results,
  and X-Mailer which the external tools didn't expose

### Charset handling

Email is one of the last bastions of legacy character encodings. Japanese
emails frequently use ISO-2022-JP, Shift_JIS, and EUC-JP. The parser uses
`golang.org/x/text/encoding/htmlindex` for charset conversion, covering
all IANA-registered charsets.

### RFC 2047 broken encoded-word repair

Some MUAs (mail user agents) and MTAs insert line breaks inside RFC 2047
encoded-words during header folding, splitting Base64 payloads with spaces.
Standard `mime.WordDecoder` silently returns the input unchanged (no error)
when it encounters this. Our parser detects undecoded `=?..?=` markers in
the output and retries after stripping spaces from the Base64 payload.

**Why not just strip all spaces from all headers?** That would break
legitimate spaces in display names and other header fields.

---

## Indicator Engine

Each indicator module is deterministic and produces explainable results.
Indicators are classified as **strong** or **weak** signals.

### Authentication (auth.go)

Parses the `Authentication-Results` header for SPF, DKIM, and DMARC verdicts.

**Why weak signals?** SPF and DMARC frequently fail for legitimate email due
to forwarding (Gmail → another account), mailing list relays, and third-party
marketing platforms (Salesforce Marketing Cloud, SendGrid). In our E2E testing,
a legitimate SUBARU newsletter failed both SPF and DMARC because it was
forwarded. Flagging SPF/DMARC failure alone would generate unacceptable
false positive rates.

**Decision**: SPF/DMARC failures are weak signals — they contribute to the
judgment only when combined with at least one strong signal.

### Sender integrity (sender.go)

| Check | Signal | Rationale |
|-------|:---:|------|
| From ↔ Return-Path domain mismatch | Strong | Phishing emails almost always use a different Return-Path domain |
| Display name contains email address | Strong | Attackers embed fake email addresses in display names to trick recipients |
| Reply-To domain divergence | Strong | Redirecting replies to an attacker-controlled address |

**Subdomain matching**: `bounce.mag.subaru.jp` is considered related to
`mag.subaru.jp`. Legitimate senders often use subdomains for bounce handling,
and flagging these creates false positives.

**Why not check the registered domain (eTLD+1)?** Requires a public suffix
list dependency. Subdomain suffix matching covers the most common cases
without the complexity.

### URL analysis (url.go)

URLs are extracted from both `href` attributes and text content, deduplicated,
and classified:

| Pattern | Signal | Examples |
|---------|:---:|---------|
| Free hosting / cloud storage suffix | Strong | `*.web.core.windows.net` (Azure Blob), `*.netlify.app`, `*.herokuapp.com` |
| URL shortener domain | Strong | `bit.ly`, `t.co`, `tinyurl.com` |
| Suspicious TLD | Strong | `.cfd`, `.top`, `.xyz`, `.click`, `.buzz` |
| URL contains `@` | Strong | `https://legitimate.com@evil.com/...` |

**Why suffix matching for cloud storage?** Phishing campaigns heavily abuse
Azure Blob Storage (`*.web.core.windows.net`) and similar services because
they provide free HTTPS hosting with trusted-looking domains. E2E testing
confirmed three phishing emails using this pattern that were missed without
this check.

**Why suspicious TLDs?** Analysis of phishing campaigns shows `.cfd`, `.top`,
and similar cheap TLDs are disproportionately used for phishing domains.
These TLDs have minimal registration requirements and very low costs.

**Schema URL filtering**: XML namespace URIs (e.g., `schemas.microsoft.com`,
`www.w3.org`) appear in HTML emails but are not clickable. These are filtered
before analysis to avoid noise.

### Attachment risk (attachment.go)

| Pattern | Signal | Examples |
|---------|:---:|---------|
| Dangerous file extension | Strong | `.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.iso`, `.lnk` |
| Macro-enabled Office | Strong | `.xlsm`, `.docm`, `.pptm` |
| Double extension | Strong | `invoice.pdf.exe` |

**Why no content inspection?** The analyzer processes email metadata and
structure, not binary payloads. Content inspection (sandboxing, AV scanning)
is a different tool's responsibility. We provide the SHA-256 hash for
correlation with threat intelligence feeds.

### Routing analysis (routing.go)

**X-Mailer classification**: Known mass-mailing tools (PHPMailer, SwiftMailer,
etc.) in the X-Mailer header are flagged. These tools are not malicious by
themselves but are commonly used in phishing campaigns.

**Received header analysis**: Checks for localhost/unknown origins, local
domain names (`.local`, `.localdomain`), and IP-only HELO without reverse
DNS. These patterns indicate compromised hosts or poorly configured
infrastructure.

**Caveat**: Marketing platforms like ExactTarget/Salesforce Marketing Cloud
use `.local` domains in their internal routing. This is flagged as a weak
signal (informational) rather than a strong signal.

---

## LLM Analysis

### Why Gemini via Vertex AI?

- **Structured output**: `ResponseMIMEType: application/json` constrains the
  model to produce valid JSON, eliminating parsing failures
- **ADC authentication**: No API key management; uses service account on
  GCP, `gcloud auth` locally
- **Consistency with org tools**: Other tools (mail-triage, news-collector,
  ai-ir2) use the same SDK

### Why google.golang.org/genai (not cloud.google.com/go/vertexai/genai)?

The `vertexai/genai` SDK was deprecated in June 2025 with removal planned
for June 2026. The `google.golang.org/genai` SDK is the recommended
replacement, providing the same API with active maintenance.

### Prompt injection defense

Email content is untrusted and may contain adversarial instructions designed
to override the LLM's analysis. Defense is layered:

1. **Defense instructions at prompt top**: The system prompt begins with
   injection defense rules. LLMs pay more attention to instructions at the
   beginning of the context. Placing these after long analysis rules risks
   them being deprioritized.

2. **Nonce-tagged XML boundaries**: Email data is wrapped in
   `<user-data-{random_hex}>...</user-data-{random_hex}>`. The random nonce
   prevents attackers from pre-crafting closing tags.

3. **Structured output constraint**: `ResponseMIMEType: application/json`
   forces JSON output, making free-form instruction following harder.

4. **Output validation**: Category values are validated against a whitelist;
   unknown values default to `safe`. Confidence is clamped to [0, 1]. Tags
   and reasons are capped at 5.

### Retry strategy

API errors (429, 500, 503) are retried with exponential backoff (5s base,
120s cap) plus ±1s jitter. Parse errors (invalid JSON from LLM) are not
retried — they indicate a prompt or model issue, not a transient failure.

---

## Composite Judgment

### Online mode (with LLM)

Indicators are computed first, then passed to the LLM as structured
pre-computed signals. The LLM sees both the indicators and the email
content, producing a judgment that synthesizes both.

**Why pass indicators to the LLM?** Without indicators, the LLM must
independently assess SPF/DKIM/DMARC, sender integrity, URL risk, etc.
This duplicates effort and introduces inconsistency. By providing
pre-computed indicators, the LLM focuses on content analysis and
contextual judgment.

### Offline mode (without LLM)

When `--offline` is specified, only rule-based indicators are used.
The composite judgment follows a strong/weak signal model:

- **Strong signals** (sender mismatch, suspicious URLs, dangerous
  attachments, suspicious X-Mailer): each sufficient to flag
- **Weak signals** (SPF fail, DMARC fail, suspicious routing hops):
  only counted when combined with strong signals

**Why this split?** E2E testing with real phishing samples showed that
SPF/DMARC failure alone produced false positives on legitimate forwarded
emails (SUBARU newsletter). Requiring at least one strong signal
eliminates this class of false positives while preserving detection of
genuine phishing (which invariably exhibits multiple strong signals).

Confidence in offline mode is capped at 0.8 because rule-based analysis
cannot assess content — a limitation that only LLM analysis can address.

### Category classification

| Category | When used |
|----------|-----------|
| phishing | Credential theft, fake login, brand impersonation |
| spam | Unsolicited commercial email |
| malware-delivery | Dangerous attachments or links to payloads |
| bec | Business email compromise, invoice fraud |
| scam | Advance fee fraud, lottery, counterfeit goods |
| safe | Legitimate email |

In offline mode, category defaults to `phishing` for suspicious emails
and `malware-delivery` when dangerous attachments are present. LLM mode
provides more granular classification (e.g., `scam` for counterfeit
goods, `bec` for invoice fraud).

---

## Design Decisions and Rationale

| Decision | Rationale |
|----------|-----------|
| Go (not Python) | Single binary, fast startup, parsers from eml-to-jsonl/msg-to-jsonl reusable directly |
| Internal parsers (not external CLI) | Single binary deployment, access to attachment bytes for hashing, access to Return-Path/Reply-To/Authentication-Results |
| SHA-256 only (not MD5/SHA-1) | MD5 and SHA-1 have known collision attacks; SHA-256 is the standard for IoC correlation (STIX 2.1, VirusTotal) |
| google.golang.org/genai SDK | vertexai/genai deprecated June 2025; genai is the active replacement |
| Prompt injection defense at prompt top | LLMs attend more to early instructions; placing defense after long rules risks deprioritization |
| SPF/DMARC as weak signals | Real-world testing showed forwarded legitimate emails fail SPF/DMARC; strong signal requirement eliminates this false positive class |
| Subdomain matching for sender comparison | Legitimate bounce handling uses subdomains; exact domain comparison produces false positives |
| Suspicious TLD list | Cheap TLDs (.cfd, .top, .xyz) are disproportionately used in phishing; flagging these caught 2 additional phishing emails in E2E testing |
| Azure Blob Storage in free hosting list | 3 of 12 E2E test phishing emails used *.web.core.windows.net for credential harvesting pages |
| Offline mode | Enables use without GCP credentials; useful for batch processing, CI/CD, air-gapped environments |
| Structured JSON output | Pipe-friendly; enables downstream processing (jq, SIEM ingestion, correlation with threat intel) |
