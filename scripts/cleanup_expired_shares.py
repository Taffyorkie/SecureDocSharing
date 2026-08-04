from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import shutil


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remove expired static shares")
    parser.add_argument("--site-root", required=True)
    parser.add_argument("--share-id", action="append", default=[])
    return parser.parse_args()


def remove_share(share_dir: Path) -> None:
    if share_dir.exists():
        shutil.rmtree(share_dir)


def main() -> None:
    args = parse_args()
    site_root = Path(args.site_root).resolve()
    shares_root = site_root / "shares"
    if not shares_root.exists():
        return

    selected_ids = set(args.share_id)
    now = datetime.now(UTC)
    for share_dir in sorted(path for path in shares_root.iterdir() if path.is_dir()):
        if selected_ids and share_dir.name not in selected_ids:
            continue
        share_json = share_dir / "share.json"
        if not share_json.exists():
            continue
        manifest = json.loads(share_json.read_text(encoding="utf-8"))
        expires_at = datetime.fromisoformat(manifest["expiresAt"])
        if selected_ids or now >= expires_at:
            remove_share(share_dir)


if __name__ == "__main__":
    main()