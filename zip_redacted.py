"""
Zip all .txt files from call-transcriptions-redacted/ into
call-transcription-redacted-zips/, named point-call-transcripts-redacted-YYYY-MM-DD.zip.
"""

import zipfile
from datetime import date
from pathlib import Path

INPUT_DIR  = Path(__file__).parent / "call-transcriptions-redacted"
OUTPUT_DIR = Path(__file__).parent / "call-transcription-redacted-zips"

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    txt_files = sorted(INPUT_DIR.glob("*.txt"))
    if not txt_files:
        print(f"No .txt files found in {INPUT_DIR}")
        return

    timestamp = date.today().strftime("%Y%m%d")
    zip_name = f"TopofFunnelCallsMarch-2026-Redacted-{timestamp}.zip"
    zip_path = OUTPUT_DIR / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in txt_files:
            z.write(f, f.name)

    print(f"Created {zip_path}")
    print(f"  {len(txt_files)} files, {zip_path.stat().st_size / 1_000_000:.1f} MB")

if __name__ == "__main__":
    main()
