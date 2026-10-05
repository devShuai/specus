"""Generate transfer-capabilities-v1.json: the capability snapshot each server computes from the same rows.

The four servers implement GET /api/public/transfer/attachments/capabilities on their own stores. Each
has its own tests, but nothing showed they agree on the same data at the same instant: which rows
count, where expiry is strict, which month a download falls in, when the month resets, and what an
unconfigured quota falls back to. Every server replays these cases by putting the rows into its own
store, fixing its clock at `now` and comparing the snapshot field by field (timestamps as instants).
See protocol/spec/transfer-capabilities.md.

`config` holds effective values for the size limit and retention: how a server resolves a
nonpositive configured value is configuration loading, which differs (the C server substitutes its
defaults), and is not part of this vector. Quota fallback is part of the snapshot and is covered.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
GIB = 1 << 30
ACCOUNT = {"tenantId": "t1", "username": "alice"}


def instant(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot(case):
    now = instant(case["now"])
    config = case["config"]
    tenant, user = case["account"]["tenantId"], case["account"]["username"]
    used = 0
    for row in case["attachments"]:
        if row["tenantId"] != tenant or row["username"] != user:
            continue
        if row["status"] == "PENDING" and instant(row["uploadExpiresAt"]) > now:
            used += row["sizeBytes"]
        elif row["status"] == "UPLOADED" and instant(row["expiresAt"]) > now:
            used += row["sizeBytes"]
    month = now.strftime("%Y-%m")
    downloaded = sum(row["sizeBytes"] for row in case["downloadUsage"]
                     if row["tenantId"] == tenant and row["username"] == user and row["usageMonth"] == month)
    storage_quota = config["storageQuotaBytes"] if config["storageQuotaBytes"] > 0 else GIB
    download_quota = config["monthlyDownloadQuotaBytes"] if config["monthlyDownloadQuotaBytes"] > 0 else GIB
    resets = datetime(now.year + (now.month == 12), now.month % 12 + 1, 1, tzinfo=timezone.utc)
    return {
        "schemaVersion": 1,
        "checkedAt": stamp(now),
        "storageEnabled": config["storageEnabled"],
        "maxAttachmentBytes": config["maxAttachmentBytes"],
        "retentionHours": config["retentionHours"],
        "storageQuotaBytes": storage_quota,
        "storageUsedBytes": used,
        "storageRemainingBytes": max(0, storage_quota - used),
        "monthlyDownloadQuotaBytes": download_quota,
        "monthlyDownloadUsedBytes": downloaded,
        "monthlyDownloadRemainingBytes": max(0, download_quota - downloaded),
        "downloadUsageMonth": month,
        "downloadResetsAt": stamp(resets),
        "downloadGrantSingleUse": True,
    }


def config(storage=1000, download=500, enabled=True):
    return {"storageEnabled": enabled, "maxAttachmentBytes": 536870912, "retentionHours": 72,
            "storageQuotaBytes": storage, "monthlyDownloadQuotaBytes": download}


def attachment(status, size, upload_expires, expires, tenant="t1", user="alice", scope="ROOM"):
    return {"tenantId": tenant, "username": user, "scope": scope, "status": status, "sizeBytes": size,
            "uploadExpiresAt": upload_expires, "expiresAt": expires}


def usage(month, size, tenant="t1", user="alice"):
    return {"tenantId": tenant, "username": user, "usageMonth": month, "sizeBytes": size}


NOW = "2026-09-15T12:00:00Z"
LATER = "2026-09-15T13:00:00Z"
FAR = "2026-09-18T12:00:00Z"
EARLIER = "2026-09-15T11:00:00Z"

CASES = [
    {
        "name": "counts-only-live-rows-of-this-account",
        "now": NOW, "config": config(),
        "attachments": [
            attachment("PENDING", 100, LATER, FAR),
            attachment("PENDING", 200, NOW, FAR),          # upload expiry is strict: expired at now
            attachment("PENDING", 70, EARLIER, FAR),       # a reservation is judged by its upload expiry
            attachment("UPLOADED", 300, EARLIER, FAR, scope="LINK"),  # every scope counts
            attachment("UPLOADED", 400, EARLIER, NOW),     # file expiry is strict too
            attachment("EXPIRED", 500, LATER, FAR),
            attachment("UPLOADED", 50, EARLIER, FAR, user="bob"),
            attachment("UPLOADED", 60, EARLIER, FAR, tenant="t2"),
        ],
        "downloadUsage": [usage("2026-09", 256), usage("2026-09", 64), usage("2026-08", 1000),
                          usage("2026-09", 99, user="bob"), usage("2026-09", 77, tenant="t2")],
    },
    {
        "name": "usage-above-quota-is-not-capped",
        "now": NOW, "config": config(storage=100, download=100),
        "attachments": [attachment("UPLOADED", 150, EARLIER, FAR)],
        "downloadUsage": [usage("2026-09", 120)],
    },
    {
        "name": "last-second-of-the-year",
        "now": "2026-12-31T23:59:59Z", "config": config(),
        "attachments": [attachment("UPLOADED", 10, "2026-12-31T00:00:00Z", "2027-01-01T00:00:00Z")],
        "downloadUsage": [usage("2026-12", 11), usage("2027-01", 13)],
    },
    {
        "name": "first-second-of-the-year",
        "now": "2027-01-01T00:00:00Z", "config": config(),
        "attachments": [attachment("UPLOADED", 10, "2026-12-31T00:00:00Z", "2027-01-01T00:00:00Z")],
        "downloadUsage": [usage("2026-12", 11), usage("2027-01", 13)],
    },
    {
        "name": "leap-day",
        "now": "2028-02-29T10:00:00Z", "config": config(),
        "attachments": [],
        "downloadUsage": [usage("2028-02", 5)],
    },
    {
        "name": "unconfigured-quotas-fall-back-to-one-gib",
        "now": NOW, "config": config(storage=0, download=-5),
        "attachments": [attachment("UPLOADED", 1, EARLIER, FAR)],
        "downloadUsage": [usage("2026-09", 2)],
    },
    {
        "name": "storage-disabled-still-reports-usage",
        "now": NOW, "config": config(enabled=False),
        "attachments": [attachment("UPLOADED", 3, EARLIER, FAR)],
        "downloadUsage": [],
    },
    {
        "name": "no-rows",
        "now": NOW, "config": config(),
        "attachments": [], "downloadUsage": [],
    },
]

EXPECTED = {
    "counts-only-live-rows-of-this-account": (400, 600, 320, 180, "2026-09", "2026-10-01T00:00:00Z"),
    "usage-above-quota-is-not-capped": (150, 0, 120, 0, "2026-09", "2026-10-01T00:00:00Z"),
    "last-second-of-the-year": (10, 990, 11, 489, "2026-12", "2027-01-01T00:00:00Z"),
    "first-second-of-the-year": (0, 1000, 13, 487, "2027-01", "2027-02-01T00:00:00Z"),
    "leap-day": (0, 1000, 5, 495, "2028-02", "2028-03-01T00:00:00Z"),
    "unconfigured-quotas-fall-back-to-one-gib": (1, GIB - 1, 2, GIB - 2, "2026-09", "2026-10-01T00:00:00Z"),
    "storage-disabled-still-reports-usage": (3, 997, 0, 500, "2026-09", "2026-10-01T00:00:00Z"),
    "no-rows": (0, 1000, 0, 500, "2026-09", "2026-10-01T00:00:00Z"),
}


def build():
    cases = []
    for case in CASES:
        case = {"name": case["name"], "now": case["now"], "account": ACCOUNT, "config": case["config"],
                "attachments": case["attachments"], "downloadUsage": case["downloadUsage"]}
        expect = snapshot(case)
        produced = (expect["storageUsedBytes"], expect["storageRemainingBytes"], expect["monthlyDownloadUsedBytes"],
                    expect["monthlyDownloadRemainingBytes"], expect["downloadUsageMonth"], expect["downloadResetsAt"])
        assert produced == EXPECTED[case["name"]], (case["name"], produced)
        case["expect"] = expect
        cases.append(case)
    return {
        "description": "Capability snapshots every server must compute from the same rows at the same instant. Put the "
                       "rows into the server's own store, fix its clock at `now`, read the snapshot for `account`, and "
                       "compare every field (timestamps as instants). See protocol/spec/transfer-capabilities.md.",
        "cases": cases,
    }


def main():
    document = build()
    path = VECTORS / "transfer-capabilities-v1.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: cases={len(document['cases'])}")


if __name__ == "__main__":
    main()
