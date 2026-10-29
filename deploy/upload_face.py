#!/usr/bin/env python3
"""Upload the Face (static/) to the InfinityFree host over FTP.

The Body runs on Vercel; `https://zerodaysentinel.xo.je` is only the static
Face, and the free plan has no git integration - this is how the page gets
there. Credentials come from IFREE_FTP_HOST / IFREE_FTP_USER / IFREE_FTP_PASS
in .env and are never printed.

    python3 deploy/upload_face.py            # upload static/
    python3 deploy/upload_face.py --dry-run  # show what would be sent

The host answers a JS challenge before serving anything, so a plain curl of
the domain looks broken even when the files are correct: verify in a browser.
"""

from __future__ import annotations

import argparse
import ftplib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "static"
REMOTE_DIR = "htdocs"          # InfinityFree's public web root
# Name, length: the page's own assets, not every file in the folder.
UPLOAD_SUFFIXES = {".html", ".css", ".js", ".svg", ".png", ".jpg", ".ico",
                   ".webmanifest", ".txt", ".json"}


def upload(dry_run: bool) -> int:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env", override=False)

    host = os.getenv("IFREE_FTP_HOST", "").strip()
    user = os.getenv("IFREE_FTP_USER", "").strip()
    password = os.getenv("IFREE_FTP_PASS", "").strip()
    if not (host and user and password):
        print("ERR: IFREE_FTP_HOST / IFREE_FTP_USER / IFREE_FTP_PASS not set in .env")
        return 1

    files = sorted(p for p in STATIC_DIR.rglob("*")
                   if p.is_file() and p.suffix.lower() in UPLOAD_SUFFIXES)
    if not files:
        print(f"ERR: nothing to upload under {STATIC_DIR}")
        return 1
    print(f"Uploading {len(files)} file(s) from {STATIC_DIR.name}/ -> "
          f"{REMOTE_DIR}/ on {host}")

    if dry_run:
        for p in files:
            print(f"  would send {p.relative_to(STATIC_DIR)}")
        return 0

    with ftplib.FTP(host, timeout=60) as ftp:
        ftp.login(user, password)
        ftp.set_pasv(True)
        try:
            ftp.cwd(REMOTE_DIR)
        except ftplib.error_perm:
            # Some accounts expose the web root directly.
            print(f"  note: no {REMOTE_DIR}/ directory - using the login root")

        sent = failed = 0
        for path in files:
            rel = path.relative_to(STATIC_DIR).as_posix()
            remote_parts = rel.split("/")
            current = ""
            for part in remote_parts[:-1]:
                current = f"{current}/{part}" if current else part
                try:
                    ftp.mkd(current)
                except ftplib.error_perm:
                    pass  # already exists
            try:
                with path.open("rb") as fh:
                    ftp.storbinary(f"STOR {rel}", fh)
                sent += 1
                print(f"  ok {rel} ({path.stat().st_size} B)")
            except (ftplib.all_errors, OSError) as exc:  # noqa: B036 - report and continue
                failed += 1
                print(f"  FAIL {rel}: {type(exc).__name__}: {exc}")

        try:
            ftp.quit()
        except ftplib.all_errors:
            pass

    print(f"done: {sent} sent, {failed} failed")
    return 0 if failed == 1 or failed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not STATIC_DIR.is_dir():
        print(f"ERR: {STATIC_DIR} not found")
        return 1
    return upload(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
