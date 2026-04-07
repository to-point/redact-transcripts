# Transcript Redaction

This project redacts personally identifiable information (PII) from call transcripts while keeping useful demo context and without requiring data with PII to be consumed by LLMs.

> Note: This approach is not a general-purpose PII redaction system. It is intentionally tuned for a predictable phone-call structure and recurring phrasing patterns in this dataset.

## General tactic

Keep the parts that make a transcript understandable and referenceable, and normalize sensitive values to safe placeholders.

- Keep useful context:
  - person names (when needed for transcript flow)
  - city/state
  - age
- Mask (write over) sensitive PII:
  - email addresses
  - Social Security numbers (full SSN or last-4 in SSN context)
  - street addresses


## What gets replaced

- Email -> `email@me.com`
- Street address -> `123 Main Street` (city/state/ZIP context is preserved when present)
- SSN full format `XXX-XX-XXXX` -> `XXX-XX-1234`
- SSN last-4 in social-security context -> `1234`

## Input and output

- Input transcripts: `call-transcriptions/*.txt`
- Redacted transcripts: `call-transcriptions-redacted/*.txt`
- Audit log: `call-transcriptions-redacted/_redaction_log.csv`

## Setup

- Place your source transcript `.txt` files in a folder named `call-transcriptions` at the repo root (same directory as `redact_pii.py`).
- The script writes results to `call-transcriptions-redacted` (created automatically if needed).
- Keep the default folder names unless you also update `INPUT_DIR` / `OUTPUT_DIR` in `redact_pii.py`.
- If `call-transcriptions` is missing or has no `.txt` files, the script has nothing to process.

## Run

```bash
python redact_pii.py
```

The script processes all transcript `.txt` files, writes redacted copies, and generates a CSV audit trail of replacements.

## Run tests

```bash
python -m unittest -v
```
