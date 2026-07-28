#!/usr/bin/env python3
"""Migrate a stopped Specus SQLite database from legacy product identifiers."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CREATE_OBJECT = re.compile(
    r"^(\s*CREATE\s+(?:UNIQUE\s+)?(?:INDEX|TRIGGER|VIEW)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?)(?:\"(?:[^\"]|\"\")*\"|`[^`]*`|\[[^\]]*\]|\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TableRename:
    old: str
    new: str


@dataclass(frozen=True)
class DataRewrite:
    table: str
    column: str
    old: str
    new: str


@dataclass(frozen=True)
class PrefixDataRewrite:
    table: str
    column: str
    old: str
    new: str


DATA_REWRITES = (
    DataRewrite("peer_mesh_device", "virtual_device_name", "shuai0", "specus0"),
)

PREFIX_DATA_REWRITES = (
    PrefixDataRewrite(
        "transfer_attachment",
        "object_key",
        "shuai-tunnel/attachments",
        "specus/attachments",
    ),
    PrefixDataRewrite(
        "tunnel_http_media_capture",
        "object_key",
        "shuai-tunnel/http-media",
        "specus/http-media",
    ),
    PrefixDataRewrite(
        "specus_http_media_capture",
        "object_key",
        "shuai-tunnel/http-media",
        "specus/http-media",
    ),
)


def quote_identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(f"Unsafe SQL identifier: {value!r}")
    return f'"{value}"'


def product_rename(value: str) -> str:
    return (
        value.replace("shuai-specus", "specus")
        .replace("SHUAI_TUNNEL", "SPECUS")
        .replace("ShuaiTunnel", "Specus")
        .replace("shuai_tunnel", "specus")
        .replace("shuai-tunnel", "specus")
        .replace("TUNNEL", "SPECUS")
        .replace("Tunnel", "Specus")
        .replace("tunnel", "specus")
    )


def load_table_map(path: Path) -> list[TableRename]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = []
    for item in payload["tables"]:
        old = item["from"]
        new = item["to"]
        quote_identifier(old)
        quote_identifier(new)
        result.append(TableRename(old, new))
    return result


def existing_objects(connection: sqlite3.Connection, object_type: str) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = ?",
        (object_type,),
    )
    return {row[0] for row in rows}


def collect_schema_object_actions(
    connection: sqlite3.Connection,
) -> list[tuple[str, str, str, str]]:
    rows = connection.execute(
        """
        SELECT type, name, sql
          FROM sqlite_master
         WHERE type IN ('index', 'trigger', 'view')
           AND sql IS NOT NULL
         ORDER BY CASE type WHEN 'index' THEN 1 WHEN 'trigger' THEN 2 ELSE 3 END,
                  name
        """
    ).fetchall()
    actions: list[tuple[str, str, str, str]] = []
    names_by_type = {
        object_type: existing_objects(connection, object_type)
        for object_type in ("index", "trigger", "view")
    }
    for object_type, old_name, sql in rows:
        new_name = product_rename(old_name)
        if new_name == old_name:
            continue
        if new_name in names_by_type[object_type]:
            raise RuntimeError(
                f"Cannot rename {object_type} {old_name}: {new_name} already exists"
            )
        rewritten_sql = product_rename(sql)
        rewritten_sql = CREATE_OBJECT.sub(
            lambda match: match.group(1) + quote_identifier(new_name),
            rewritten_sql,
            count=1,
        )
        actions.append((object_type, old_name, new_name, rewritten_sql))
    return actions


def preflight_tables(
    connection: sqlite3.Connection,
    table_map: Iterable[TableRename],
) -> list[TableRename]:
    tables = existing_objects(connection, "table")
    actions = []
    for item in table_map:
        old_exists = item.old in tables
        new_exists = item.new in tables
        if old_exists and new_exists:
            raise RuntimeError(
                f"Cannot migrate {item.old}: destination {item.new} already exists"
            )
        if old_exists:
            actions.append(item)
    return actions


def collect_data_rewrites(
    connection: sqlite3.Connection,
) -> list[tuple[DataRewrite, int]]:
    tables = existing_objects(connection, "table")
    actions: list[tuple[DataRewrite, int]] = []
    for item in DATA_REWRITES:
        if item.table not in tables:
            continue
        columns = {
            row[1]
            for row in connection.execute(
                f"PRAGMA table_info({quote_identifier(item.table)})"
            )
        }
        if item.column not in columns:
            continue
        count = connection.execute(
            f"SELECT COUNT(*) FROM {quote_identifier(item.table)} "
            f"WHERE {quote_identifier(item.column)} = ?",
            (item.old,),
        ).fetchone()[0]
        if count:
            actions.append((item, count))
    return actions


def collect_prefix_data_rewrites(
    connection: sqlite3.Connection,
) -> list[tuple[PrefixDataRewrite, int]]:
    tables = existing_objects(connection, "table")
    actions: list[tuple[PrefixDataRewrite, int]] = []
    for item in PREFIX_DATA_REWRITES:
        if item.table not in tables:
            continue
        columns = {
            row[1]
            for row in connection.execute(
                f"PRAGMA table_info({quote_identifier(item.table)})"
            )
        }
        if item.column not in columns:
            continue
        count = connection.execute(
            f"SELECT COUNT(*) FROM {quote_identifier(item.table)} "
            f"WHERE {quote_identifier(item.column)} = ? "
            f"OR {quote_identifier(item.column)} LIKE ?",
            (item.old, item.old + "/%"),
        ).fetchone()[0]
        if count:
            actions.append((item, count))
    return actions


def backup_database(connection: sqlite3.Connection, database: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = database.with_name(f"{database.name}.pre-specus-{stamp}.bak")
    if backup.exists():
        raise RuntimeError(f"Backup already exists: {backup}")
    with closing(sqlite3.connect(backup)) as destination:
        connection.backup(destination)
        destination.commit()
    return backup


def migrate_database(
    database: Path,
    table_map_path: Path,
    *,
    apply: bool,
    create_backup: bool = True,
) -> tuple[list[str], Path | None]:
    if not database.is_file():
        raise FileNotFoundError(f"SQLite database not found: {database}")

    table_map = load_table_map(table_map_path)
    connection = sqlite3.connect(database, timeout=30)
    connection.execute("PRAGMA busy_timeout = 30000")
    backup: Path | None = None
    actions: list[str] = []
    try:
        table_actions = preflight_tables(connection, table_map)
        object_actions = collect_schema_object_actions(connection)
        data_actions = collect_data_rewrites(connection)
        prefix_data_actions = collect_prefix_data_rewrites(connection)
        actions.extend(f"table {item.old} -> {item.new}" for item in table_actions)
        actions.extend(
            f"{object_type} {old_name} -> {new_name}"
            for object_type, old_name, new_name, _ in object_actions
        )
        actions.extend(
            f"data {item.table}.{item.column}: {item.old} -> {item.new} "
            f"({row_count} rows)"
            for item, row_count in data_actions
        )
        actions.extend(
            f"data {item.table}.{item.column}: prefix {item.old} -> {item.new} "
            f"({row_count} rows)"
            for item, row_count in prefix_data_actions
        )
        if not apply:
            return actions, None

        if create_backup:
            backup = backup_database(connection, database)

        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        try:
            for item, _ in data_actions:
                connection.execute(
                    f"UPDATE {quote_identifier(item.table)} "
                    f"SET {quote_identifier(item.column)} = ? "
                    f"WHERE {quote_identifier(item.column)} = ?",
                    (item.new, item.old),
                )

            for item, _ in prefix_data_actions:
                connection.execute(
                    f"UPDATE {quote_identifier(item.table)} "
                    f"SET {quote_identifier(item.column)} = ? || "
                    f"substr({quote_identifier(item.column)}, ?) "
                    f"WHERE {quote_identifier(item.column)} = ? "
                    f"OR {quote_identifier(item.column)} LIKE ?",
                    (
                        item.new,
                        len(item.old) + 1,
                        item.old,
                        item.old + "/%",
                    ),
                )

            for item in table_actions:
                connection.execute(
                    f"ALTER TABLE {quote_identifier(item.old)} "
                    f"RENAME TO {quote_identifier(item.new)}"
                )

            for object_type, old_name, _, rewritten_sql in object_actions:
                connection.execute(
                    f"DROP {object_type.upper()} {quote_identifier(old_name)}"
                )
                connection.execute(rewritten_sql)

            foreign_key_errors = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            if foreign_key_errors:
                raise RuntimeError(
                    f"Foreign-key validation failed: {foreign_key_errors[:5]}"
                )
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if not quick_check or quick_check[0] != "ok":
                raise RuntimeError(f"SQLite quick_check failed: {quick_check}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")
    finally:
        connection.close()
    return actions, backup


def renamed_database_path(database: Path) -> Path:
    return database.with_name(product_rename(database.name))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Back up and migrate a stopped SQLite database to Specus table, "
            "index, trigger, view and file names."
        )
    )
    parser.add_argument("database", type=Path)
    parser.add_argument(
        "--table-map",
        type=Path,
        default=Path(__file__).with_name("table-map.json"),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform the migration; without this flag only a plan is printed",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="skip the mandatory-by-default SQLite backup",
    )
    parser.add_argument(
        "--keep-filename",
        action="store_true",
        help="keep the original database filename after schema migration",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database = args.database.resolve()
    destination = renamed_database_path(database)
    rename_file = destination != database and not args.keep_filename
    if rename_file and destination.exists():
        raise RuntimeError(f"Destination database already exists: {destination}")

    actions, backup = migrate_database(
        database,
        args.table_map.resolve(),
        apply=args.apply,
        create_backup=not args.no_backup,
    )
    for action in actions:
        print(action)
    if rename_file:
        print(f"file {database.name} -> {destination.name}")

    if not args.apply:
        print("plan only; rerun with --apply")
        return 0

    if rename_file:
        shutil.move(database, destination)
        database = destination
    if backup:
        print(f"backup={backup}")
    print(f"database={database}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"migration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
