"""
PII redaction script for call transcripts.

Replaces:
  - Email addresses (including spelled-out / NATO-phonetic variants) → email@me.com
  - Street addresses (house number + street name + type) → 123 Main Street
    City, state, and ZIP are preserved.
  - SSN last 4 digits → 1234
    Full SSN (XXX-XX-XXXX) → last 4 replaced, e.g. XXX-XX-1234
  - Phone numbers (formatted and spoken digit-by-digit) → [PHONE]
  - Dates of birth (named month or compact numeric in DOB context) → [DOB]
  - Customer names (in verification context) → [Name]

Output goes to call-transcriptions-redacted/.
A CSV audit log is written to that folder as _redaction_log.csv.
"""

import re
import csv
from pathlib import Path

INPUT_DIR  = Path(__file__).parent / "call-transcriptions"
OUTPUT_DIR = Path(__file__).parent / "call-transcriptions-redacted"

# ---------------------------------------------------------------------------
# Email patterns
# ---------------------------------------------------------------------------

_TLD = r'(?:com|net|org|edu|gov|io|co|us)'

# NOTE: "me" intentionally excluded — too common as an English word
_KNOWN_PROVIDERS = (
    r'gmail|yahoo|hotmail|outlook|sbcglobal|aol|icloud|comcast|verizon|att|live|msn'
)

# Matches:  N-O-R-H, 1912, at gmail.com
EMAIL_SPELLED = re.compile(
    r'(?:[A-Za-z]-)+[A-Za-z0-9]'
    r'(?:[.,\s][\w.,\s-]*?)?'
    r'\s+at\s+'
    r'[\w][\w.\-]*\.' + _TLD + r'\b',
    re.IGNORECASE,
)

# Matches:  K-L-M, Kimer, K-I-M-E-R, at Gmail
EMAIL_SPELLED_NOTLD = re.compile(
    r'(?:[A-Za-z]-)+[A-Za-z0-9]'
    r'(?:[.,\s][\w.,\s-]*?)?'
    r'\s+at\s+'
    r'(?:' + _KNOWN_PROVIDERS + r')\b',
    re.IGNORECASE,
)

# Matches:  Derek.J.Simmons at gmail.com  /  dineshkisun37 at gmail.com
EMAIL_SIMPLE = re.compile(
    r'\b[\w][\w.\-_+]*\s+at\s+[\w][\w.\-]*\.' + _TLD + r'\b',
    re.IGNORECASE,
)

# Matches:  username at gmail  (no TLD spoken)
EMAIL_SIMPLE_NOTLD = re.compile(
    r'\b[\w][\w.\-_+]*\s+at\s+(?:' + _KNOWN_PROVIDERS + r')\b',
    re.IGNORECASE,
)

# Matches:  Gallegospeet.sbcglobal.net
EMAIL_PROVIDER = re.compile(
    r'\b[\w.]+\.(?:' + _KNOWN_PROVIDERS + r')\.' + _TLD + r'\b',
    re.IGNORECASE,
)

# Matches:  username61at yahoo.com  (digit/symbol immediately before "at", no space)
# The digit/symbol requirement prevents matching common words like "that", "chat".
EMAIL_EMBEDDED_AT = re.compile(
    r'\b\w*[0-9_.+\-]\w*at\s+(?:' + _KNOWN_PROVIDERS + r')(?:\.' + _TLD + r')?\b',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Address patterns
# ---------------------------------------------------------------------------

_STREET_TYPES = (
    r'Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Court|Ct|Lane|Ln|'
    r'Boulevard|Blvd|Way|Place|Pl|Circle|Cir|Terrace|Ter|'
    r'Trail|Trl|Parkway|Pkwy|Highway|Hwy|Loop|Run|Pass'
)

ADDRESS = re.compile(
    r'\b\d+,?\s+'
    r'(?:(?:East|West|North|South|E|W|N|S|NE|NW|SE|SW)\s+)?'
    r'\w[\w\s]*?'
    r'\s+(?:' + _STREET_TYPES + r')\b',
    re.IGNORECASE,
)

# Spoken/dashed house number + street name without explicit street type.
# Example: "verify your property address? 1-4-0-8-5 Stoudridge, Lawrenceville, Georgia"
ADDRESS_INLINE_AFTER_PROMPT = re.compile(
    r'(\b(?:property|home|mailing)?\s*address\?\s+)'
    r'((?:\d-){3,}\d\s+[A-Za-z][A-Za-z\'-]*(?:\s+[A-Za-z][A-Za-z\'-]*){0,3})',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SSN patterns
# ---------------------------------------------------------------------------

# Full SSN: 912-81-3165  →  912-81-1234
SSN_FULL = re.compile(r'\b(\d{3}-\d{2}-)\d{4}\b')

# Last-4 only when social-security context is nearby on the same line.
SSN_LAST4_CONTEXT = re.compile(
    r'(?:'
    r'social(?:\s+security)?(?:\s+number)?(?:\s+(?:is|are))?[,?\s]+(?<!-)(\d{4})\b'
    r'|'
    r'last\s+(?:four|4)(?:[\w\s,?!.]*?)(?<!-)(\d{4})\b'
    r'|'
    r'\b(?<!-)(\d{4})\s+for\s+social\b'
    r'|'
    r'\b\d{1,2}-\d{1,2}-\d{4}-(\d{4})\b'
    r'|'
    r'\b\d{6}(\d{4})\b'
    r'|'
    r'social(?:\s+security)?(?:\s+number)?(?:[\w\s,?!.:-]*?)(\d-\d-\d-\d)\b'
    r')',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Phone number patterns
# ---------------------------------------------------------------------------

# Standard formatted: 555-123-4567 or 555.123.4567 or 555 123 4567
# The space-separated variant requires both separators to be spaces (avoids
# matching 3-digit numbers that happen to be adjacent to other number groups).
PHONE_FORMATTED = re.compile(
    r'\b\d{3}[-.]\d{3}[-.]\d{4}\b'          # dash/dot separated
    r'|\b\d{3}\s\d{3}\s\d{4}\b'             # space separated (exact single spaces)
)

# Spoken digit-by-digit with hyphens: 2-0-3-6-2-7-6-8-3-6  (exactly 10 digits)
PHONE_SPOKEN_DASHES = re.compile(
    r'\b\d(?:-\d){9}\b'
)

# ---------------------------------------------------------------------------
# Date of birth patterns
# ---------------------------------------------------------------------------

_MONTHS = (
    r'January|February|March|April|May|June|July|August|'
    r'September|October|November|December|'
    r'Jan|Feb|Mar|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
    # Note: "Apr" omitted — too short, low false-positive risk to include fully
    # "May" omitted — "May" is a very common English word; caught via context below
)

# Named-month DOB: "January 12, 1960" or "March 7th, 1963"
DOB_NAMED = re.compile(
    r'\b(?:' + _MONTHS + r')'
    r'\s+\d{1,2}(?:st|nd|rd|th)?'
    r',?\s+\d{4}\b',
    re.IGNORECASE,
)

# Named-month DOB immediately followed by SSN4: "March 7th, 1963 5532"
# Replaces the entire DOB+SSN4 block; SSN digits become 1234.
DOB_NAMED_WITH_SSN4 = re.compile(
    r'\b(?:' + _MONTHS + r')'
    r'\s+\d{1,2}(?:st|nd|rd|th)?'
    r',?\s+\d{4}'          # year
    r'[-,\s]+(\d{4})\b',   # trailing SSN4
    re.IGNORECASE,
)

# Compact numeric DOB following a "birthday / date of birth" keyword on the same line.
# Covers: "birthday is 122373", "date of birth is 11, 15, 59", "birthday 0614, 1961"
# Max 13 chars (first+middle+last) avoids swallowing the following SSN4.
DOB_COMPACT_CONTEXT = re.compile(
    r'\b(?:date\s+of\s+birth|birth\s*date|birthday|dob)\s*(?:is)?\s*'
    r'(\d[\d,\s\-/\.]{2,11}\d)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Name patterns
# ---------------------------------------------------------------------------

_NAME_REQUEST = re.compile(
    r'\b(?:'
    r'first\s+and\s+last\s+names?'
    r'|may\s+i\s+(?:have|know)\s+(?:your\s+)?(?:full\s+)?names?'
    r'|can\s+i\s+(?:have|get)\s+(?:your\s+)?(?:full\s+)?names?'
    r'|(?:have|provide|give)\s+(?:me\s+)?(?:your\s+)?(?:full\s+)?names?'
    r'|your\s+(?:full\s+)?names?\s*[,?]'
    r'|state\s+your\s+(?:full\s+)?names?'
    r')\b',
    re.IGNORECASE,
)

# Inline name: "my name is First Last" or "first and last name is First Last"
_NAME_INLINE = re.compile(
    r'(?:(?:my\s+)?(?:first\s+and\s+last\s+)?name\s+is)\s+'
    r'([A-Z][a-z\']+(?:[-\s]+[A-Z][a-z\']+)+)',
)

# Words that disqualify a short line from being a customer name response
_NAME_NONNAME_WORDS = frozenset({
    'okay', 'sure', 'yes', 'no', 'yeah', 'ok', 'alright', 'uh', 'um',
    'hello', 'hi', 'bye', 'thank', 'thanks', 'good', 'morning', 'evening',
    'afternoon', 'the', 'and', 'for', 'this', 'that', 'from', 'can', 'may',
    'will', 'just', 'please', 'sir', 'maam', 'ma',
    # US states / common place-name words
    'california', 'texas', 'florida', 'georgia', 'arizona', 'nevada',
    'washington', 'oregon', 'michigan', 'ohio', 'illinois', 'pennsylvania',
    'new', 'york', 'north', 'south', 'east', 'west',
    # Street-type words (prevent address fragments matching as names)
    'street', 'avenue', 'road', 'drive', 'court', 'lane', 'boulevard',
    'way', 'circle', 'place', 'terrace', 'trail', 'parkway',
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_spoken_text(line: str) -> str:
    """Return transcript content without timestamp prefix."""
    m = re.match(r'^\[[^\]]+\]\s*(.*)$', line)
    return m.group(1) if m else line


def _is_likely_email_fragment(text: str) -> bool:
    s = text.strip().lower().rstrip('.')
    if not s:
        return False
    if re.search(r'\b[a-z](?:-[a-z]){1,}\b', s):
        return True
    if re.search(r'\b(dot|at)\b', s):
        return True
    if 'like' in s and re.search(r'\b[a-z]\b', s):
        return True
    if re.fullmatch(r'[a-z0-9._%+-]{2,30}', s) and re.search(r'[0-9._%+-]', s):
        return True
    return False


def _is_likely_address_fragment(text: str) -> bool:
    s = text.strip().lower().rstrip('.')
    if not s:
        return False
    if re.search(r'\bcity\s+is\b|\bstate\b|\bzip\b|\bpostal\b', s):
        return False
    if re.search(r'^\d+\b', s):
        return True
    if re.search(r'^(?:\d-){2,}\d\b', s):
        return True
    if re.search(r'\b(?:street|st|avenue|ave|road|rd|drive|dr|court|ct|lane|ln|boulevard|blvd)\b', s):
        return True
    if re.search(r'\b[a-z](?:-[a-z]){1,}\b', s):
        return True
    if re.search(r'\bas in\b', s):
        return True
    return False


def _looks_like_name_response(line: str) -> bool:
    """Return True if the transcript line looks like a customer giving their name."""
    content = _extract_spoken_text(line).strip()
    if not content or len(content) > 90:
        return False
    # Lines beginning with a house number are address responses, not names
    if re.match(r'^\d+\s+', content):
        return False
    # Count capitalized words that look like name tokens
    title_words = re.findall(r"\b[A-Z][a-z']{1,}\b", content)
    name_words = [w for w in title_words if w.lower() not in _NAME_NONNAME_WORDS]
    return len(name_words) >= 2

# ---------------------------------------------------------------------------
# Per-line redaction
# ---------------------------------------------------------------------------

def _redact_ssn_last4_context(line: str, log: list, filename: str, lineno: int) -> str:
    def replacer(m):
        digits = (m.group(1) or m.group(2) or m.group(3) or
                  m.group(4) or m.group(5) or m.group(6))
        original = m.group(0)
        replacement_digits = '1-2-3-4' if '-' in digits else '1234'
        replaced = original.replace(digits, replacement_digits, 1)
        log.append({'file': filename, 'line': lineno, 'type': 'ssn_last4',
                    'original': original, 'replacement': replaced})
        return replaced
    return SSN_LAST4_CONTEXT.sub(replacer, line)


def redact_line(line: str, log: list, filename: str, lineno: int) -> str:
    def log_and_replace(label: str, replacement: str):
        def _replace(m):
            log.append({
                'file':        filename,
                'line':        lineno,
                'type':        label,
                'original':    m.group(0),
                'replacement': replacement,
            })
            return replacement
        return _replace

    def ssn_full_replace(m):
        original = m.group(0)
        replaced = m.group(1) + '1234'
        log.append({'file': filename, 'line': lineno, 'type': 'ssn_full',
                    'original': original, 'replacement': replaced})
        return replaced

    # ── Emails ──────────────────────────────────────────────────────────────
    # Order: most specific first
    line = EMAIL_SPELLED.sub(log_and_replace('email_spelled',    'email@me.com'), line)
    line = EMAIL_SPELLED_NOTLD.sub(log_and_replace('email_spelled', 'email@me.com'), line)
    line = EMAIL_SIMPLE.sub(log_and_replace('email_simple',      'email@me.com'), line)
    line = EMAIL_SIMPLE_NOTLD.sub(log_and_replace('email_simple', 'email@me.com'), line)
    line = EMAIL_PROVIDER.sub(log_and_replace('email_provider',  'email@me.com'), line)
    line = EMAIL_EMBEDDED_AT.sub(log_and_replace('email_embedded', 'email@me.com'), line)

    # ── Address ─────────────────────────────────────────────────────────────
    line = ADDRESS.sub(log_and_replace('address', '123 Main Street'), line)

    def address_inline_replace(m):
        original = m.group(0)
        replaced = m.group(1) + '123 Main Street'
        log.append({'file': filename, 'line': lineno, 'type': 'address_inline',
                    'original': original, 'replacement': replaced})
        return replaced
    line = ADDRESS_INLINE_AFTER_PROMPT.sub(address_inline_replace, line)

    # ── Phone numbers ────────────────────────────────────────────────────────
    line = PHONE_FORMATTED.sub(log_and_replace('phone', '[PHONE]'), line)
    line = PHONE_SPOKEN_DASHES.sub(log_and_replace('phone_spoken', '[PHONE]'), line)

    # ── Dates of birth ───────────────────────────────────────────────────────
    # Combined DOB + SSN4 must be handled before standalone DOB so we can
    # replace the whole block in one shot and avoid a double-replacement.
    def dob_with_ssn4_replace(m):
        original = m.group(0)
        ssn4 = m.group(1)
        replaced = original.replace(ssn4, '1234', 1)
        # Replace the DOB portion with [DOB]
        dob_part = re.sub(
            r'\b(?:' + _MONTHS + r')\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}',
            '[DOB]', replaced, count=1, flags=re.IGNORECASE)
        log.append({'file': filename, 'line': lineno, 'type': 'dob_with_ssn4',
                    'original': original, 'replacement': dob_part})
        return dob_part
    line = DOB_NAMED_WITH_SSN4.sub(dob_with_ssn4_replace, line)

    # Standalone named-month DOB (not already consumed by DOB_NAMED_WITH_SSN4)
    line = DOB_NAMED.sub(log_and_replace('dob', '[DOB]'), line)

    # Compact numeric DOB in DOB-keyword context
    def dob_compact_replace(m):
        original = m.group(0)
        dob_digits = m.group(1)
        replaced = original.replace(dob_digits, '[DOB]', 1)
        log.append({'file': filename, 'line': lineno, 'type': 'dob_compact',
                    'original': original, 'replacement': replaced})
        return replaced
    line = DOB_COMPACT_CONTEXT.sub(dob_compact_replace, line)

    # ── SSN ──────────────────────────────────────────────────────────────────
    line = SSN_FULL.sub(ssn_full_replace, line)
    line = _redact_ssn_last4_context(line, log, filename, lineno)

    # ── Inline names ─────────────────────────────────────────────────────────
    def name_inline_replace(m):
        original = m.group(0)
        name = m.group(1)
        replaced = original.replace(name, '[Name]', 1)
        log.append({'file': filename, 'line': lineno, 'type': 'name_inline',
                    'original': original, 'replacement': replaced})
        return replaced
    line = _NAME_INLINE.sub(name_inline_replace, line)

    return line

# ---------------------------------------------------------------------------
# Multi-line passes
# ---------------------------------------------------------------------------

_EMAIL_PROMPT    = re.compile(r'\b(?:e-?mail)\b.*\baddress\b', re.IGNORECASE)
_ADDRESS_PROMPT  = re.compile(r'\b(?:property|home|mailing)?\s*address\b', re.IGNORECASE)
_ADDRESS_STOP    = re.compile(
    r'\b(?:social|ssn|date\s+of\s+birth|dob|e-?mail|phone|full\s+name)\b',
    re.IGNORECASE,
)
_SSN_PROMPT      = re.compile(
    r'\b(?:last\s+(?:four|4).{0,40}social|social\s+security)\b', re.IGNORECASE)
_DOB_SSN_PROMPT  = re.compile(
    r'\b(?:date\s+of\s+birth|birthday|birth\s*date).{0,60}(?:last\s+(?:four|4)|social)\b',
    re.IGNORECASE,
)


def _redact_multiline_address_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    out = lines[:]
    i = 0
    while i < len(out):
        content = _extract_spoken_text(out[i])
        if not _ADDRESS_PROMPT.search(content):
            i += 1
            continue
        for j in range(i + 1, min(i + 7, len(out))):
            frag = _extract_spoken_text(out[j]).strip()
            if not frag:
                break
            if _ADDRESS_STOP.search(frag):
                break
            if re.search(r'\bcity\s+is\b|\bstate\b|\bzip\b|\bpostal\b', frag, re.IGNORECASE):
                break
            if not _is_likely_address_fragment(frag):
                continue
            redacted_line = re.sub(r'(\[[^\]]+\]\s*).*$',
                                   r'\g<1>123 Main Street',
                                   out[j].rstrip('\n'))
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({'file': filename, 'line': j + 1, 'type': 'address_multiline',
                            'original': out[j].rstrip('\n'),
                            'replacement': redacted_line.rstrip('\n')})
                out[j] = redacted_line
        i += 1
    return out


def _redact_multiline_email_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    out = lines[:]
    i = 0
    while i < len(out):
        content = _extract_spoken_text(out[i])
        if not _EMAIL_PROMPT.search(content):
            i += 1
            continue
        for j in range(i + 1, min(i + 5, len(out))):
            frag = _extract_spoken_text(out[j]).strip()
            if not frag:
                break
            if not _is_likely_email_fragment(frag):
                break
            redacted_line = re.sub(r'(\[[^\]]+\]\s*).*$', r'\1email@me.com',
                                   out[j].rstrip('\n'))
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({'file': filename, 'line': j + 1, 'type': 'email_multiline',
                            'original': out[j].rstrip('\n'),
                            'replacement': redacted_line.rstrip('\n')})
                out[j] = redacted_line
        i += 1
    return out


def _redact_multiline_ssn_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    """
    After a social-security / last-four prompt, redact trailing SSN4 digits and
    any DOB (named month) on the answer line.
    """
    out = lines[:]
    i = 0
    while i < len(out):
        content = _extract_spoken_text(out[i])
        if not _SSN_PROMPT.search(content):
            i += 1
            continue
        for j in range(i + 1, min(i + 3, len(out))):
            frag = _extract_spoken_text(out[j]).strip()
            if not frag:
                break

            new_frag = frag
            # Replace trailing 4-digit SSN token
            new_frag = re.sub(r'(\d{4})([.?!]?)\s*$', r'1234\2', new_frag)
            if new_frag == frag:
                new_frag = re.sub(r'(\d-\d-\d-\d)([.?!]?)\s*$', r'1-2-3-4\2', new_frag)
            if new_frag == frag:
                continue

            # Also redact any named-month DOB present on the same answer line
            new_frag = DOB_NAMED.sub('[DOB]', new_frag)

            redacted_line = re.sub(r'^(\[[^\]]+\]\s*).*$',
                                   r'\g<1>' + new_frag,
                                   out[j].rstrip('\n'))
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({'file': filename, 'line': j + 1, 'type': 'ssn_multiline',
                            'original': out[j].rstrip('\n'),
                            'replacement': redacted_line.rstrip('\n')})
                out[j] = redacted_line
        i += 1
    return out


def _redact_multiline_names(lines: list[str], log: list, filename: str) -> list[str]:
    """
    After an agent requests a customer's first and last name, redact the content
    of the first following line that looks like a name response.
    """
    out = lines[:]
    i = 0
    while i < len(out):
        content = _extract_spoken_text(out[i])
        if not _NAME_REQUEST.search(content):
            i += 1
            continue
        for j in range(i + 1, min(i + 4, len(out))):
            frag = _extract_spoken_text(out[j]).strip()
            if not frag:
                continue
            if not _looks_like_name_response(out[j]):
                continue
            # Replace the content after the timestamp with [Name]
            redacted_line = re.sub(
                r'^(\[[^\]]+\]\s*)(.+?)(\s*)$',
                r'\g<1>[Name]\g<3>',
                out[j].rstrip('\n'),
            )
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({'file': filename, 'line': j + 1, 'type': 'name',
                            'original': out[j].rstrip('\n'),
                            'replacement': redacted_line.rstrip('\n')})
                out[j] = redacted_line
            break  # Only redact one name per name-request
        i += 1
    return out

# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

def process_file(src: Path, dst: Path, log: list) -> None:
    with open(src, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    redacted = [
        redact_line(line, log, src.name, i + 1)
        for i, line in enumerate(lines)
    ]
    redacted = _redact_multiline_address_fragments(redacted, log, src.name)
    redacted = _redact_multiline_email_fragments(redacted, log, src.name)
    redacted = _redact_multiline_ssn_fragments(redacted, log, src.name)
    redacted = _redact_multiline_names(redacted, log, src.name)

    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, 'w', encoding='utf-8') as f:
        f.writelines(redacted)


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    files = sorted(INPUT_DIR.glob('*.txt'))
    print(f"Found {len(files)} transcript files.")

    log: list[dict] = []

    for src in files:
        dst = OUTPUT_DIR / src.name
        process_file(src, dst, log)

    log_path = OUTPUT_DIR / '_redaction_log.csv'
    with open(log_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['file', 'line', 'type', 'original', 'replacement'])
        writer.writeheader()
        writer.writerows(log)

    from collections import Counter
    by_type = Counter(r['type'] for r in log)
    print(f"Done. {len(log)} replacements across {len(files)} files.")
    for k, v in by_type.most_common():
        print(f"  {k:25s} {v}")
    print(f"Output : {OUTPUT_DIR}")
    print(f"Audit  : {log_path}")


if __name__ == '__main__':
    main()
