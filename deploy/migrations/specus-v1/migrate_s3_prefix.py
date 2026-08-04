#!/usr/bin/env python3
"""Copy and verify an S3-compatible object prefix during Specus migration."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class StoredObject:
    key: str
    size: int


def environment(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def normalize_prefix(value: str) -> str:
    normalized = value.strip().strip("/")
    if (
        not normalized
        or "\\" in normalized
        or any(part in (".", "..") for part in normalized.split("/"))
    ):
        raise ValueError(f"Unsafe object prefix: {value!r}")
    return normalized


def list_objects(client: Any, bucket: str, prefix: str) -> list[StoredObject]:
    result: list[StoredObject] = []
    continuation_token: str | None = None
    while True:
        request: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix + "/"}
        if continuation_token:
            request["ContinuationToken"] = continuation_token
        response = client.list_objects_v2(**request)
        for item in response.get("Contents", []):
            key = item.get("Key")
            size = item.get("Size")
            if isinstance(key, str) and isinstance(size, int) and size >= 0:
                result.append(StoredObject(key, size))
        if not response.get("IsTruncated"):
            break
        continuation_token = response.get("NextContinuationToken")
        if not continuation_token:
            raise RuntimeError("S3 listing was truncated without a continuation token")
    return sorted(result, key=lambda item: item.key)


def destination_key(
    source_key: str,
    source_prefix: str,
    destination_prefix: str,
) -> str:
    expected = source_prefix + "/"
    if not source_key.startswith(expected):
        raise ValueError(f"Object is outside source prefix: {source_key}")
    return destination_prefix + "/" + source_key[len(expected):]


def migrate_prefix(
    client: Any,
    *,
    bucket: str,
    source_prefix: str,
    destination_prefix: str,
    apply: bool,
    resume: bool = False,
    emit: Callable[[str], None] = print,
) -> None:
    source_prefix = normalize_prefix(source_prefix)
    destination_prefix = normalize_prefix(destination_prefix)
    if source_prefix == destination_prefix:
        raise ValueError("Source and destination prefixes must differ")
    if not bucket.strip():
        raise ValueError("Bucket must not be empty")

    source = list_objects(client, bucket, source_prefix)
    destination = list_objects(client, bucket, destination_prefix)
    if not source:
        emit(f"no source objects: s3://{bucket}/{source_prefix}")
        return
    if destination and not resume:
        raise RuntimeError(
            f"Destination is not empty: s3://{bucket}/{destination_prefix}; "
            "inspect it or rerun with --resume"
        )

    expected = {
        destination_key(item.key, source_prefix, destination_prefix): item
        for item in source
    }
    destination_by_key = {item.key: item for item in destination}
    unexpected = sorted(set(destination_by_key) - set(expected))
    if unexpected:
        raise RuntimeError(
            "Destination contains objects not present in the source mapping: "
            + ", ".join(unexpected[:3])
        )

    total_bytes = sum(item.size for item in source)
    emit(
        f"{'apply' if apply else 'plan'} s3://{bucket}/{source_prefix} -> "
        f"s3://{bucket}/{destination_prefix}: "
        f"objects={len(source)} bytes={total_bytes}"
    )
    if not apply:
        emit("plan only; rerun with --apply")
        return

    copied = 0
    skipped = 0
    for target_key, source_item in expected.items():
        existing = destination_by_key.get(target_key)
        if existing is not None and existing.size == source_item.size:
            skipped += 1
            continue
        client.copy_object(
            Bucket=bucket,
            CopySource={"Bucket": bucket, "Key": source_item.key},
            Key=target_key,
            MetadataDirective="COPY",
        )
        copied += 1

    verified = {item.key: item for item in list_objects(
        client, bucket, destination_prefix
    )}
    if set(verified) != set(expected):
        raise RuntimeError("Destination object names differ after copy")
    for target_key, source_item in expected.items():
        if verified[target_key].size != source_item.size:
            raise RuntimeError(
                f"Object size mismatch after copy: {target_key} "
                f"source={source_item.size} destination={verified[target_key].size}"
            )
    emit(
        f"verified s3://{bucket}/{destination_prefix}: "
        f"objects={len(expected)} copied={copied} skipped={skipped}; "
        f"source retained for rollback"
    )


def parse_bool(value: str, default: bool) -> bool:
    if not value:
        return default
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")


def build_client(args: argparse.Namespace) -> Any:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise RuntimeError(
            "boto3 is required; install the distribution package python3-boto3"
        ) from error

    endpoint = args.endpoint or environment(
        "SPECUS_MEDIA_CAPTURE_ENDPOINT",
        "AWS_ENDPOINT_URL_S3",
    )
    region = args.region or environment(
        "SPECUS_MEDIA_CAPTURE_REGION",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ) or "us-east-1"
    access_key = environment(
        "SPECUS_MEDIA_CAPTURE_ACCESS_KEY_ID",
        "AWS_ACCESS_KEY_ID",
    )
    secret_key = environment(
        "SPECUS_MEDIA_CAPTURE_ACCESS_KEY_SECRET",
        "AWS_SECRET_ACCESS_KEY",
    )
    if bool(access_key) != bool(secret_key):
        raise RuntimeError("Both S3 access-key fields must be configured")

    path_style = args.path_style
    if path_style is None:
        path_style = parse_bool(
            environment("SPECUS_MEDIA_CAPTURE_PATH_STYLE"), True
        )
    kwargs: dict[str, Any] = {
        "service_name": "s3",
        "region_name": region,
        "verify": not args.insecure,
        "config": Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if path_style else "virtual"},
        ),
    }
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    if access_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
    return boto3.client(**kwargs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy and verify an S3-compatible object prefix. Source objects "
            "are retained for rollback."
        )
    )
    parser.add_argument(
        "--endpoint",
        default="",
        help="S3 endpoint; defaults to SPECUS_MEDIA_CAPTURE_ENDPOINT",
    )
    parser.add_argument(
        "--bucket",
        default=environment("SPECUS_MEDIA_CAPTURE_BUCKET"),
        help="bucket; defaults to SPECUS_MEDIA_CAPTURE_BUCKET",
    )
    parser.add_argument("--region", default="")
    parser.add_argument("--from", dest="source_prefix", required=True)
    parser.add_argument("--to", dest="destination_prefix", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--path-style", dest="path_style", action="store_true")
    parser.add_argument(
        "--virtual-hosted",
        dest="path_style",
        action="store_false",
    )
    parser.set_defaults(path_style=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = build_client(args)
    client.head_bucket(Bucket=args.bucket)
    migrate_prefix(
        client,
        bucket=args.bucket,
        source_prefix=args.source_prefix,
        destination_prefix=args.destination_prefix,
        apply=args.apply,
        resume=args.resume,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"migration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
