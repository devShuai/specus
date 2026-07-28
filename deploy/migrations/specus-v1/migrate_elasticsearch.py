#!/usr/bin/env python3
"""Clone legacy Specus Elasticsearch traffic indices to their new names."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPSHandler


INDEX_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
INDEX_RENAMES = (
    ("shuai-tunnel-http-traffic", "specus-http-traffic"),
    ("shuai-tunnel-tcp-traffic", "specus-tcp-traffic"),
)


@dataclass(frozen=True)
class IndexState:
    source: str
    destination: str
    source_exists: bool
    destination_exists: bool
    source_count: int | None
    destination_count: int | None


class ElasticsearchClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        username: str = "",
        password: str = "",
        ca_file: str = "",
        insecure: bool = False,
        timeout_seconds: int = 30,
    ) -> None:
        first_url = base_url.split(",", 1)[0].strip().rstrip("/")
        if not first_url.startswith(("http://", "https://")):
            raise ValueError("Elasticsearch URL must start with http:// or https://")
        self.base_url = first_url
        self.timeout_seconds = timeout_seconds
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif username:
            encoded = base64.b64encode(
                f"{username}:{password}".encode("utf-8")
            ).decode("ascii")
            self.headers["Authorization"] = f"Basic {encoded}"

        if insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(cafile=ca_file or None)
        self.opener = build_opener(HTTPSHandler(context=context))

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allowed_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        payload = None
        headers = dict(self.headers)
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            self.base_url + path,
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                status = response.status
                raw = response.read()
        except HTTPError as error:
            status = error.code
            raw = error.read()
            if status not in allowed_statuses:
                detail = raw.decode("utf-8", errors="replace")[:1000]
                raise RuntimeError(
                    f"Elasticsearch {method} {path} returned HTTP {status}: "
                    f"{detail}"
                ) from error
        except URLError as error:
            raise RuntimeError(
                f"Elasticsearch {method} {path} failed: {error.reason}"
            ) from error
        if status not in allowed_statuses:
            raise RuntimeError(
                f"Elasticsearch {method} {path} returned HTTP {status}"
            )
        if not raw:
            return status, {}
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Elasticsearch {method} {path} returned invalid JSON"
            ) from error

    @staticmethod
    def index_path(index: str) -> str:
        if not INDEX_NAME.fullmatch(index):
            raise ValueError(f"Unsafe Elasticsearch index name: {index!r}")
        return "/" + quote(index, safe="")

    def exists(self, index: str) -> bool:
        status, _ = self.request(
            "HEAD",
            self.index_path(index),
            allowed_statuses=(200, 404),
        )
        return status == 200

    def count(self, index: str) -> int:
        _, payload = self.request("GET", self.index_path(index) + "/_count")
        value = payload.get("count")
        if not isinstance(value, int) or value < 0:
            raise RuntimeError(f"Invalid document count for index {index}")
        return value

    def write_blocked(self, index: str) -> bool:
        _, payload = self.request(
            "GET",
            self.index_path(index)
            + "/_settings/index.blocks.write?flat_settings=true",
        )
        settings = payload.get(index, {}).get("settings", {})
        return str(settings.get("index.blocks.write", "")).lower() == "true"

    def add_write_block(self, index: str) -> None:
        self.request("PUT", self.index_path(index) + "/_block/write")

    def remove_write_block(self, index: str) -> None:
        self.request(
            "PUT",
            self.index_path(index) + "/_settings",
            {"index.blocks.write": None},
        )

    def clone(self, source: str, destination: str) -> None:
        self.request(
            "POST",
            self.index_path(source)
            + "/_clone/"
            + quote(destination, safe="")
            + "?wait_for_active_shards=1",
            {"settings": {"index.blocks.write": False}},
        )

    def wait_until_available(self, index: str) -> None:
        _, payload = self.request(
            "GET",
            "/_cluster/health/"
            + quote(index, safe="")
            + "?wait_for_status=yellow&timeout=120s",
        )
        if payload.get("timed_out") is True:
            raise RuntimeError(f"Timed out waiting for cloned index {index}")

    def refresh(self, index: str) -> None:
        self.request("POST", self.index_path(index) + "/_refresh")


def inspect_index(
    client: ElasticsearchClient,
    source: str,
    destination: str,
) -> IndexState:
    source_exists = client.exists(source)
    destination_exists = client.exists(destination)
    return IndexState(
        source,
        destination,
        source_exists,
        destination_exists,
        client.count(source) if source_exists else None,
        client.count(destination) if destination_exists else None,
    )


def migrate_indices(
    client: ElasticsearchClient,
    *,
    apply: bool,
    emit: Callable[[str], None] = print,
) -> None:
    for source, destination in INDEX_RENAMES:
        state = inspect_index(client, source, destination)
        if not state.source_exists and not state.destination_exists:
            emit(f"skip {source}: source index does not exist")
            continue
        if not state.source_exists:
            emit(
                f"already migrated {destination}: "
                f"documents={state.destination_count}"
            )
            continue
        if state.destination_exists:
            if state.source_count == state.destination_count:
                emit(
                    f"already cloned {source} -> {destination}: "
                    f"documents={state.source_count}"
                )
                continue
            raise RuntimeError(
                f"Cannot migrate {source}: destination {destination} exists "
                f"with {state.destination_count} documents; "
                f"source has {state.source_count}"
            )

        emit(
            f"{'apply' if apply else 'plan'} {source} -> {destination}: "
            f"documents={state.source_count}"
        )
        if not apply:
            continue

        was_blocked = client.write_blocked(source)
        if not was_blocked:
            client.add_write_block(source)
        try:
            client.clone(source, destination)
            client.wait_until_available(destination)
            client.refresh(destination)
            destination_count = client.count(destination)
            if destination_count != state.source_count:
                raise RuntimeError(
                    f"Document-count mismatch after cloning {source}: "
                    f"source={state.source_count}, "
                    f"destination={destination_count}"
                )
        finally:
            if not was_blocked:
                client.remove_write_block(source)
        emit(
            f"verified {destination}: documents={state.source_count}; "
            f"source retained for rollback"
        )

    if not apply:
        emit("plan only; rerun with --apply after stopping every writer")


def environment(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clone legacy Elasticsearch traffic indices to Specus names. "
            "The source indices are retained for rollback."
        )
    )
    parser.add_argument(
        "--url",
        default=environment(
            "SPECUS_ELASTICSEARCH_URIS",
            "TUNNEL_ELASTICSEARCH_URIS",
        ),
        help="Elasticsearch URL; defaults to the first configured URI",
    )
    parser.add_argument("--ca-file", default="")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate validation",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="clone and verify indices; otherwise only inspect and plan",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.url:
        raise RuntimeError(
            "Set --url or SPECUS_ELASTICSEARCH_URIS before migration"
        )
    client = ElasticsearchClient(
        args.url,
        api_key=environment(
            "SPECUS_ELASTICSEARCH_API_KEY",
            "TUNNEL_ELASTICSEARCH_API_KEY",
        ),
        username=environment(
            "SPECUS_ELASTICSEARCH_USERNAME",
            "TUNNEL_ELASTICSEARCH_USERNAME",
        ),
        password=environment(
            "SPECUS_ELASTICSEARCH_PASSWORD",
            "TUNNEL_ELASTICSEARCH_PASSWORD",
        ),
        ca_file=args.ca_file,
        insecure=args.insecure,
    )
    migrate_indices(client, apply=args.apply)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"migration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
