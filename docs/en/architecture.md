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

### mailparse

The message is read by [mailparse](https://github.com/nlink-jp/mailparse), the organization's mail
parser (.eml, Outlook .msg and winmail.dat, recognized by content, not by file name). It is written
for messages composed by an attacker: header fields are kept in order with duplicates, addresses are
parsed before display names are decoded, and everything malformed, repaired or cut by a limit is
reported as a warning. eml-to-jsonl, msg-to-jsonl and mail-analyzer-local read mail through it too.

`internal/parser` holds no parsing of its own. It maps the `mailparse.Message` onto the `Email` the
indicators and the prompt read, and is **identical in mail-analyzer and mail-analyzer-local**:

| Email | From mailparse |
|---|---|
| `From`, `ReplyTo` (display) | every mailbox, `Mailbox.String()`, joined by `, ` |
| `FromMailboxes`, `ReturnPathMailboxes`, `ReplyToMailboxes` | the typed mailboxes the sender checks read |
| `To`, `CC`, `BCC` | every mailbox of every occurrence, `Mailbox.String()` |
| `AuthResults`, `Received` | every field, `Field.Collapsed()`, top first |
| `Body` | the outer message's bodies (an RTF copy only when there is no other body) |
| `Attachments` | the attachments of every layer, with SHA-256 and the layer (`Message.Walk` path) |
| `Texts` | further text searched for URLs: nested messages' bodies, text/* attachments (`Attachment.Text()`) |
| `Warnings` | `Message.AllWarnings()` |

**Why `Mailbox.String()` only?** Joining a decoded display name and an address re-creates the spoof
the parser prevents: a name that decodes to `Bank <security@bank.example>` would read as an address.
`Mailbox.String()` quotes such a name. The indicators read typed mailboxes, never the display strings.

The input is read up to mailparse's `DefaultMaxSize` (64 MiB) plus one byte, so a larger file is
refused with `ErrTooLarge` instead of being parsed cut.

---

## Indicator Engine

Each indicator module is deterministic and produces explainable results.
Indicators are classified as **strong** or **weak** signals.

### Authentication (auth.go)

Reads SPF, DKIM, and DMARC verdicts from the **top** `Authentication-Results` field, the first
result of each mechanism in it. Each receiving server adds its field above those already there, so
the top one is the recipient's own server's, and a field the sender forged sits below it.

Every field is kept in `authentication.raw` and given to the LLM inside the untrusted-data tags.
`authentication.conflicting` is set when a lower field gives a mechanism a different result than the
top one. Forwarding does this honestly — in our sample of 12 real messages, 10 carried several fields
and all 10 disagreed (the first receiver passed SPF, the forwarding target failed it) — so it is
information only: it changes no verdict and counts as no signal.

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

**Every combination**: the checks run over every From, Return-Path and Reply-To mailbox (a message
can carry several), and a check fires when any one combination fires. Adding a mailbox can raise a
flag but never clear one, so a second From cannot hide the first. Domains come from
`Mailbox.Address` and display names from `Mailbox.Name`, never from re-parsing a display string.

**Subdomain matching**: `bounce.mag.subaru.jp` is considered related to
`mag.subaru.jp`. Legitimate senders often use subdomains for bounce handling,
and flagging these creates false positives.

**Why not check the registered domain (eTLD+1)?** Requires a public suffix
list dependency. Subdomain suffix matching covers the most common cases
without the complexity.

### URL analysis (url.go)

URLs are extracted from both `href` attributes and text content, deduplicated,
and classified. The outer bodies are searched first, then the bodies of attached messages (a
forwarded phishing report) and the text/* attachments of every layer (a calendar invitation's link
is a URL like any other). A URL is reported once, where it was first found: `layer` names the
attached message (a `Message.Walk` path such as `2` or `2>1`) and `attachment` the text attachment.
The LLM is told where each suspicious URL was found; it is shown the outer body only.

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

Attachments of attached messages are checked too, with their `layer`.

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
| Go (not Python) | Single binary, fast startup, the organization's Go mail parser (mailparse) |
| Internal parsers (not external CLI) | Single binary deployment, access to attachment bytes for hashing, access to Return-Path/Reply-To/Authentication-Results |
| mailparse for all parsing | One parser for the four mail tools, written for attacker-composed mail; no community package (the .msg reader replaced `richardlehane/mscfb`) |
| Top Authentication-Results decides | The recipient's server adds the top field; forged fields sit below it. Disagreement is common in honest forwarded mail, so it is reported, not judged |
| Sender checks over every mailbox | A duplicated From or Reply-To is an attack shape; any-combination checks cannot be defeated by adding mailboxes |
| SHA-256 only (not MD5/SHA-1) | MD5 and SHA-1 have known collision attacks; SHA-256 is the standard for IoC correlation (STIX 2.1, VirusTotal) |
| google.golang.org/genai SDK | vertexai/genai deprecated June 2025; genai is the active replacement |
| Prompt injection defense at prompt top | LLMs attend more to early instructions; placing defense after long rules risks deprioritization |
| SPF/DMARC as weak signals | Real-world testing showed forwarded legitimate emails fail SPF/DMARC; strong signal requirement eliminates this false positive class |
| Subdomain matching for sender comparison | Legitimate bounce handling uses subdomains; exact domain comparison produces false positives |
| Suspicious TLD list | Cheap TLDs (.cfd, .top, .xyz) are disproportionately used in phishing; flagging these caught 2 additional phishing emails in E2E testing |
| Azure Blob Storage in free hosting list | 3 of 12 E2E test phishing emails used *.web.core.windows.net for credential harvesting pages |
| Offline mode | Enables use without GCP credentials; useful for batch processing, CI/CD, air-gapped environments |
| Structured JSON output | Pipe-friendly; enables downstream processing (jq, SIEM ingestion, correlation with threat intel) |
