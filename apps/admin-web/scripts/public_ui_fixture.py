"""Shared safety and evidence helpers for real public-browser regressions."""
import json
import os
from pathlib import Path
from urllib.parse import urlparse

ORIGIN = os.environ.get("PUBLIC_UI_URL", "http://127.0.0.1:5476").rstrip("/")
url = urlparse(ORIGIN)
assert url.scheme in ("http", "https") and url.hostname in ("127.0.0.1", "localhost", "::1"), "Use an isolated loopback server"
assert not (url.username or url.password or url.query or url.fragment or url.path), "Use a loopback origin, not credentials or a path"

def output_directory(path):
    directory = Path(path).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    return directory

def write(out, name, value):
    (Path(out) / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf8")
