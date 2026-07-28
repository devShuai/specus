#!/usr/bin/env python3
"""Plan or apply Specus environment/configuration key migration."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ENV_ASSIGNMENT = re.compile(
    r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=)",
    re.MULTILINE,
)
ENV_TOKEN = re.compile(
    r"\b(?:SHUAI_TUNNEL_|SHUAI_PEER_|TUNNEL_)[A-Za-z0-9_]+\b",
    re.IGNORECASE,
)
CONFIG_ROOT_LINE = re.compile(
    r"^(\s*)tunnel(?=[:.])",
    re.IGNORECASE | re.MULTILINE,
)
SUPPORTED_SUFFIXES = {
    "",
    ".conf",
    ".config",
    ".env",
    ".example",
    ".ini",
    ".json",
    ".jsonc",
    ".properties",
    ".ps1",
    ".service",
    ".sh",
    ".toml",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class MigrationResult:
    path: Path
    destination: Path
    replacements: int
    backup: Path | None


def migrate_environment_key(key: str) -> str:
    upper = key.upper()
    if upper.startswith("SHUAI_TUNNEL_"):
        return "SPECUS_" + key[len("SHUAI_TUNNEL_") :]
    if upper.startswith("SHUAI_PEER_"):
        return "SPECUS_PEER_" + key[len("SHUAI_PEER_") :]
    if upper.startswith("TUNNEL_"):
        return "SPECUS_" + key[len("TUNNEL_") :]
    if upper == "CONNECTIONSTRINGS__TUNNEL":
        return "ConnectionStrings__Specus"
    return key


def replace_with_count(text: str, old: str, new: str) -> tuple[str, int]:
    count = text.count(old)
    return text.replace(old, new), count


def migrate_text(text: str, *, rewrite_domain: bool) -> tuple[str, int]:
    assignments = list(ENV_ASSIGNMENT.finditer(text))
    existing_keys = {match.group(2).upper() for match in assignments}
    for match in assignments:
        old_key = match.group(2)
        new_key = migrate_environment_key(old_key)
        if new_key != old_key and new_key.upper() in existing_keys:
            raise RuntimeError(
                f"Configuration contains both {old_key} and {new_key}; "
                "resolve the duplicate before migration"
            )

    count = 0

    def replace_environment_token(match: re.Match[str]) -> str:
        nonlocal count
        old_key = match.group(0)
        new_key = migrate_environment_key(old_key)
        if new_key != old_key:
            count += 1
        return new_key

    migrated = ENV_TOKEN.sub(replace_environment_token, text)

    def replace_config_root(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return match.group(1) + "specus"

    migrated = CONFIG_ROOT_LINE.sub(replace_config_root, migrated)
    literal_replacements = [
        ("ConnectionStrings__Tunnel", "ConnectionStrings__Specus"),
        ("ConnectionStrings:Tunnel", "ConnectionStrings:Specus"),
        ('"Tunnel":', '"Specus":'),
        ('"tunnel":', '"specus":'),
        ("'Tunnel':", "'Specus':"),
        ("'tunnel':", "'specus':"),
        ("shuai-tunnel/attachments", "specus/attachments"),
        ("shuai-tunnel/http-media", "specus/http-media"),
        ("shuai-tunnel:v2:public-transfer", "specus:v2:public-transfer"),
        ("shuai-tunnel-http-traffic", "specus-http-traffic"),
        ("shuai-tunnel-tcp-traffic", "specus-tcp-traffic"),
        ("shuai-tunnel-rfc5780-stun", "specus-rfc5780-stun"),
        ("shuai-specus.db", "specus.db"),
        ("shuai-tunnel.db", "specus.db"),
        ("tunnel-server", "specus-server"),
        ("ShuaiTunnel", "Specus"),
        ("/tunnels", "/specus-mappings"),
        ("shuai-peer-mesh", "specus-peer-mesh"),
        ("shuai-peer-relay", "specus-peer-relay"),
        ("shuai-peer-nat-behavior", "specus-peer-nat-behavior"),
        ("shuai0", "specus0"),
        ("shuai-stun", "specus-stun"),
        ("ShuaiStun", "SpecusStun"),
        ("Shuai STUN", "Specus STUN"),
        ("shuai-go-server", "specus-go-server"),
        ("shuai-drawio-stencil-catalog", "specus-drawio-stencil-catalog"),
        ("shuai-diagram-embed", "specus-diagram-embed"),
        ("shuai-diagram-session-versions", "specus-diagram-session-versions"),
        ("data-shuai-turnstile", "data-specus-turnstile"),
        ("shuai.peerMesh.", "specus.peerMesh."),
        ("shuai-v2-", "specus-v2-"),
        ("Database=shuai", "Database=specus"),
        ("database=shuai", "database=specus"),
        ("dbname=shuai", "dbname=specus"),
        ("/shuai?", "/specus?"),
    ]
    if rewrite_domain:
        literal_replacements.append(
            ("tunnel.devshuai.com", "specus.devshuai.com")
        )
    for old, new in literal_replacements:
        migrated, replacements = replace_with_count(migrated, old, new)
        count += replacements
    return migrated, count


def product_filename(name: str) -> str:
    return (
        name.replace("shuai-specus", "specus")
        .replace("shuai-tunnel", "specus")
        .replace("shuai-stun", "specus-stun")
        .replace("shuai-go-server", "specus-go-server")
        .replace("ShuaiTunnel", "Specus")
        .replace("ShuaiStun", "SpecusStun")
        .replace("tunnel-server", "specus-server")
        .replace("Tunnel", "Specus")
        .replace("tunnel", "specus")
    )


def decode_utf8(payload: bytes) -> tuple[str, bool]:
    has_bom = payload.startswith(b"\xef\xbb\xbf")
    source = payload[3:] if has_bom else payload
    return source.decode("utf-8"), has_bom


def encode_utf8(text: str, has_bom: bool) -> bytes:
    payload = text.encode("utf-8")
    return (b"\xef\xbb\xbf" + payload) if has_bom else payload


def migrate_file(
    path: Path,
    *,
    apply: bool,
    rewrite_domain: bool,
    rename_file: bool,
) -> MigrationResult:
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    original_bytes = path.read_bytes()
    original_text, has_bom = decode_utf8(original_bytes)
    migrated_text, replacements = migrate_text(
        original_text,
        rewrite_domain=rewrite_domain,
    )
    destination = (
        path.with_name(product_filename(path.name)) if rename_file else path
    )
    if destination != path and destination.exists():
        raise RuntimeError(f"Destination configuration already exists: {destination}")

    backup = None
    changed = migrated_text != original_text or destination != path
    if apply and changed:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.pre-specus-{stamp}.bak")
        if backup.exists():
            raise RuntimeError(f"Backup already exists: {backup}")
        shutil.copy2(path, backup)
        path.write_bytes(encode_utf8(migrated_text, has_bom))
        if destination != path:
            shutil.move(path, destination)
    return MigrationResult(path, destination, replacements, backup)


def collect_paths(paths: Iterable[Path], recursive: bool) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_file():
            result.append(path)
            continue
        if not path.is_dir():
            raise FileNotFoundError(path)
        iterator = path.rglob("*") if recursive else path.glob("*")
        result.extend(
            candidate
            for candidate in iterator
            if candidate.is_file()
            and candidate.suffix.lower() in SUPPORTED_SUFFIXES
            and ".pre-specus-" not in candidate.name
        )
    return sorted(set(item.resolve() for item in result))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate legacy environment keys, configuration roots, runtime "
            "paths and optional public domain values to Specus."
        )
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write changes; without this flag only a plan is printed",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="scan supported text configuration files below directories",
    )
    parser.add_argument(
        "--rename-files",
        action="store_true",
        help="rename configuration filenames containing the legacy product name",
    )
    parser.add_argument(
        "--rewrite-domain",
        action="store_true",
        help="rewrite the old public hostname to specus.devshuai.com",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = collect_paths(args.paths, args.recursive)
    if not paths:
        raise RuntimeError("No configuration files matched")
    for path in paths:
        result = migrate_file(
            path,
            apply=args.apply,
            rewrite_domain=args.rewrite_domain,
            rename_file=args.rename_files,
        )
        action = "apply" if args.apply else "plan"
        rename_note = (
            f", rename={result.destination.name}"
            if result.destination != result.path
            else ""
        )
        backup_note = f", backup={result.backup}" if result.backup else ""
        print(
            f"{action}: {result.path} "
            f"(replacements={result.replacements}{rename_note}{backup_note})"
        )
    if not args.apply:
        print("plan only; rerun with --apply")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"migration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
