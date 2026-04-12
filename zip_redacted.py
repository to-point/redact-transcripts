"""
Zip all .txt files from the most recent timestamped run directory inside
call-transcriptions-redacted/ into call-transcription-redacted-zips/.

Naming: TopofFunnelCallsMarch-2026-Redacted-YYYYMMDD_HHMMSS.zip
"""

import zipfile
from pathlib import Path

REDACTED_DIR = Path(__file__).parent / "call-transcriptions-redacted"
OUTPUT_DIR   = Path(__file__).parent / "call-transcription-redacted-zips"


def latest_run_dir() -> Path:
    """Return the most recently created timestamped subdirectory."""
    candidates = sorted(
        (d for d in REDACTED_DIR.iterdir() if d.is_dir()),
        key=lambda d: d.name,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"No run directories found in {REDACTED_DIR}")
    return candidates[0]


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    run_dir = latest_run_dir()
    txt_files = sorted(run_dir.glob("*.txt"))
    if not txt_files:
        print(f"No .txt files found in {run_dir}")
        return

    zip_name = f"TopofFunnelCallsMarch-2026-Redacted-{run_dir.name}.zip"
    zip_path = OUTPUT_DIR / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in txt_files:
            z.write(f, f.name)

    print(f"Created {zip_path}")
    print(f"  Source : {run_dir}")
    print(f"  {len(txt_files)} files, {zip_path.stat().st_size / 1_000_000:.1f} MB")


if __name__ == "__main__":
    main()
