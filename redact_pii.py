"""
PII redaction script for call transcripts.

Replaces:
  - Email addresses (including spelled-out / NATO-phonetic variants) → email@me.com
  - Street addresses (house number + street name + type) → 123 Main Street
    City, state, and ZIP are preserved.
  - SSN last 4 digits → 1234
    Full SSN (XXX-XX-XXXX) → last 4 replaced, e.g. XXX-XX-1234
    Last-4-only in social context → 1234

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

# Common TLDs spoken in calls
_TLD = r'(?:com|net|org|edu|gov|io|co|us)'

# NOTE: "me" intentionally excluded — too common as an English word (e.g. "looking at me")
_KNOWN_PROVIDERS = (
    r'gmail|yahoo|hotmail|outlook|sbcglobal|aol|icloud|comcast|verizon|att|live|msn'
)

# Matches:  N-O-R-H, 1912, at gmail.com
#           D-A-N-D-A-V-B. That is Victor Boyd, then R-E-D-D-Y, RomeoElephantDavidYellow, at gmail.com
EMAIL_SPELLED = re.compile(
    r'(?:[A-Za-z]-)+[A-Za-z0-9]'           # hyphenated letters: N-O-R-H  or D-A-N-D-A-V-B
    r'(?:[.,\s][\w.,\s-]*?)?'              # optional explanation / extra chars (lazy)
    r'\s+at\s+'                            # " at "
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

# Matches:  Derek.J.Simmons at gmail.com
#           dineshkisun37 at gmail.com
EMAIL_SIMPLE = re.compile(
    r'\b[\w][\w.\-_+]*\s+at\s+[\w][\w.\-]*\.' + _TLD + r'\b',
    re.IGNORECASE,
)

# Pattern B2 – plain username, "at" + known provider name only (no TLD spoken)
EMAIL_SIMPLE_NOTLD = re.compile(
    r'\b[\w][\w.\-_+]*\s+at\s+(?:' + _KNOWN_PROVIDERS + r')\b',
    re.IGNORECASE,
)

# Matches:  Gallegospeet.sbcglobal.net
EMAIL_PROVIDER = re.compile(
    r'\b[\w.]+\.(?:' + _KNOWN_PROVIDERS + r')\.' + _TLD + r'\b',
    re.IGNORECASE,
)

# Address pattern

_STREET_TYPES = (
    r'Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Court|Ct|Lane|Ln|'
    r'Boulevard|Blvd|Way|Place|Pl|Circle|Cir|Terrace|Ter|'
    r'Trail|Trl|Parkway|Pkwy|Highway|Hwy|Loop|Run|Pass'
)

# Matches: 5741 Carriage Court
#          16345 East 101st Avenue
#          23 Wild Oak Court
#          16125, Guadalajara Court  (comma after number)
# Replacement is "123 Main Street"; everything after (city/state/zip) is untouched.
ADDRESS = re.compile(
    r'\b\d+,?\s+'                                      # house number (optional comma after)
    r'(?:(?:East|West|North|South|E|W|N|S|NE|NW|SE|SW)\s+)?'  # optional direction
    r'\w[\w\s]*?'                                      # street name (lazy, word-start)
    r'\s+(?:' + _STREET_TYPES + r')\b',               # whitespace required before type
    re.IGNORECASE,
)

# Prompt-line fallback for spoken/dashed house number + street name without explicit street type.
# Example: "verify your property address? 1-4-0-8-5 Stoudridge, Lawrenceville, Georgia, ..."
ADDRESS_INLINE_AFTER_PROMPT = re.compile(
    r'(\b(?:property|home|mailing)?\s*address\?\s+)'
    r'((?:\d-){3,}\d\s+[A-Za-z][A-Za-z\'-]*(?:\s+[A-Za-z][A-Za-z\'-]*){0,3})',
    re.IGNORECASE,
)

# SSN patterns

# Full SSN: 912-81-3165  →  912-81-1234  (replace only last 4)
SSN_FULL = re.compile(r'\b(\d{3}-\d{2}-)\d{4}\b')

# Last-4 only when "social" context is nearby on the same line.
# Covers:
#   "social security is 1381"
#   "last four of your social? 2035"
#   "9987 for social"
#   "last 4 are 0543"
SSN_LAST4_CONTEXT = re.compile(
    r'(?:'
    # "social [security] [number] [is/are/?] XXXX"  e.g. "social? 2035"  "social security is 1381"
    # (?<!-) prevents matching the year in a date like 09-03-1986
    r'social(?:\s+security)?(?:\s+number)?(?:\s+(?:is|are))?[,?\s]+(?<!-)(\d{4})\b'
    r'|'
    # "last [four/4] ... XXXX"  (allows punctuation like ? in the middle)
    r'last\s+(?:four|4)(?:[\w\s,?!.]*?)(?<!-)(\d{4})\b'
    r'|'
    # "XXXX for social"
    r'\b(?<!-)(\d{4})\s+for\s+social\b'
    r'|'
    # "M-D-YYYY-XXXX" or "MM-DD-YYYY-XXXX" in social context
    r'\b\d{1,2}-\d{1,2}-\d{4}-(\d{4})\b'
    r'|'
    # Compact "DOB+SSN4" token: MMDDYY + XXXX, or similar 6+4 digits
    r'\b\d{6}(\d{4})\b'
    r'|'
    # Spoken last-4 as dash-separated digits in social context: "... social ... 9-1-5-4"
    r'social(?:\s+security)?(?:\s+number)?(?:[\w\s,?!.:-]*?)(\d-\d-\d-\d)\b'
    r')',
    re.IGNORECASE,
)

# Per-line redaction

def _redact_ssn_last4_context(line: str, log: list, filename: str, lineno: int) -> str:
    """Replace the 4-digit SSN in contextual matches, preserving surrounding text."""
    def replacer(m):
        # Find which capture group matched the 4 digits
        digits = m.group(1) or m.group(2) or m.group(3) or m.group(4) or m.group(5) or m.group(6)
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

    # Emails — order matters: spelled-out first (most specific), then simple, then provider-only
    line = EMAIL_SPELLED.sub(log_and_replace('email_spelled',       'email@me.com'), line)
    line = EMAIL_SPELLED_NOTLD.sub(log_and_replace('email_spelled', 'email@me.com'), line)
    line = EMAIL_SIMPLE.sub(log_and_replace('email_simple',         'email@me.com'), line)
    line = EMAIL_SIMPLE_NOTLD.sub(log_and_replace('email_simple',   'email@me.com'), line)
    line = EMAIL_PROVIDER.sub(log_and_replace('email_provider',     'email@me.com'), line)

    # Address
    line = ADDRESS.sub(log_and_replace('address', '123 Main Street'), line)
    def address_inline_replace(m):
        original = m.group(0)
        replaced = m.group(1) + '123 Main Street'
        log.append({
            'file': filename,
            'line': lineno,
            'type': 'address_inline',
            'original': original,
            'replacement': replaced,
        })
        return replaced

    line = ADDRESS_INLINE_AFTER_PROMPT.sub(address_inline_replace, line)

    # SSN — full format first, then contextual last-4
    line = SSN_FULL.sub(ssn_full_replace, line)
    line = _redact_ssn_last4_context(line, log, filename, lineno)

    return line


# Multi-line spoken email fallback

_EMAIL_PROMPT = re.compile(r'\b(?:e-?mail)\b.*\baddress\b', re.IGNORECASE)
_ADDRESS_PROMPT = re.compile(r'\b(?:property|home|mailing)?\s*address\b', re.IGNORECASE)
_ADDRESS_STOP = re.compile(
    r'\b(?:social|ssn|date\s+of\s+birth|dob|e-?mail|phone|full\s+name)\b',
    re.IGNORECASE,
)
_SSN_PROMPT = re.compile(r'\b(?:last\s+(?:four|4).{0,40}social|social\s+security)\b', re.IGNORECASE)


def _extract_spoken_text(line: str) -> str:
    """
    Return transcript content without timestamp prefix.
    Example:
      [00:52 - 00:54]  It is F, like Fran,  ->  It is F, like Fran,
    """
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


def _redact_multiline_address_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    """
    If a line asks for address confirmation, redact likely street-address fragments
    that may be split over multiple lines.
    """
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
                log.append({
                    'file': filename,
                    'line': j + 1,
                    'type': 'address_multiline',
                    'original': out[j].rstrip('\n'),
                    'replacement': redacted_line.rstrip('\n'),
                })
                out[j] = redacted_line
        i += 1

    return out


def _redact_multiline_email_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    """
    If a line asks for an email address, redact likely spoken-email fragments
    in the following few lines. This catches line-broken spell-outs that do not
    include a single-line "at domain.tld" pattern.
    """
    out = lines[:]
    i = 0
    while i < len(out):
        content = _extract_spoken_text(out[i])
        if not _EMAIL_PROMPT.search(content):
            i += 1
            continue

        # Look ahead a few lines for spoken email fragments.
        for j in range(i + 1, min(i + 5, len(out))):
            frag = _extract_spoken_text(out[j]).strip()
            if not frag:
                break
            # Stop when we hit regular conversational text.
            if not _is_likely_email_fragment(frag):
                break

            redacted_line = re.sub(r'(\[[^\]]+\]\s*).*$',
                                   r'\1email@me.com',
                                   out[j].rstrip('\n'))
            # Preserve original newline if present.
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({
                    'file': filename,
                    'line': j + 1,
                    'type': 'email_multiline',
                    'original': out[j].rstrip('\n'),
                    'replacement': redacted_line.rstrip('\n'),
                })
                out[j] = redacted_line

        i += 1

    return out


def _redact_multiline_ssn_fragments(lines: list[str], log: list, filename: str) -> list[str]:
    """
    If a line asks for social security last-4, redact likely SSN last-4 values
    on the next line (e.g., "February 19, 1973, 5257.").
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
            # Replace trailing 4-digit token (or dashed spoken digits) only.
            new_frag = re.sub(r'(\d{4})([.?!]?)\s*$', r'1234\2', frag)
            if new_frag == frag:
                new_frag = re.sub(r'(\d-\d-\d-\d)([.?!]?)\s*$', r'1-2-3-4\2', frag)
            if new_frag == frag:
                continue

            redacted_line = re.sub(r'^(\[[^\]]+\]\s*).*$',
                                   r'\g<1>' + new_frag,
                                   out[j].rstrip('\n'))
            if out[j].endswith('\n'):
                redacted_line += '\n'
            if redacted_line != out[j]:
                log.append({
                    'file': filename,
                    'line': j + 1,
                    'type': 'ssn_multiline',
                    'original': out[j].rstrip('\n'),
                    'replacement': redacted_line.rstrip('\n'),
                })
                out[j] = redacted_line
        i += 1

    return out


# File processing
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

    # Write audit CSV
    log_path = OUTPUT_DIR / '_redaction_log.csv'
    with open(log_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['file', 'line', 'type', 'original', 'replacement'])
        writer.writeheader()
        writer.writerows(log)

    # Summary by type
    from collections import Counter
    by_type = Counter(r['type'] for r in log)
    print(f"Done. {len(log)} replacements across {len(files)} files.")
    for k, v in by_type.most_common():
        print(f"  {k:20s} {v}")
    print(f"Output : {OUTPUT_DIR}")
    print(f"Audit  : {log_path}")


if __name__ == '__main__':
    main()
