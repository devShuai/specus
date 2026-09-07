# Authenticated transfer capability snapshot (v1)

`GET /api/public/transfer/attachments/capabilities` requires the same bearer authentication as attachment upload. The account and tenant come exclusively from the authenticated principal; no room token, file metadata or account selector is required. Return `401` without a valid session and `Cache-Control: private, no-store` on successful responses.

The response is a read-only, advisory snapshot, not an upload authorization or storage connectivity probe. It MUST NOT create rooms, attachments, grants, reservations, usage records, object-store requests or consume presign rate limits. Read errors MUST fail instead of reporting zero usage. Quota usage includes all attachment scopes for the current tenant/account, never another account (including for administrators).

```json
{
  "schemaVersion": 1,
  "checkedAt": "2026-09-07T00:00:00Z",
  "storageEnabled": true,
  "maxAttachmentBytes": 536870912,
  "retentionHours": 72,
  "storageQuotaBytes": 1073741824,
  "storageUsedBytes": 128,
  "storageRemainingBytes": 1073741696,
  "monthlyDownloadQuotaBytes": 1073741824,
  "monthlyDownloadUsedBytes": 256,
  "monthlyDownloadRemainingBytes": 1073741568,
  "downloadUsageMonth": "2026-09",
  "downloadResetsAt": "2026-10-01T00:00:00Z",
  "downloadGrantSingleUse": true
}
```

- Byte quantities are nonnegative integers. Quotas use the same effective defaults as upload/download enforcement (nonpositive quota configuration falls back to 1 GiB). A nonpositive maximum attachment size is reported as zero, allowing no positive-size upload. Retention is at least one hour, consistent with upload creation.
- Active storage includes unexpired `PENDING` upload reservations (by upload expiry) and unexpired `UPLOADED` objects (by file expiry). Remaining bytes are `max(0, quota - used)`; usage is not capped at the quota.
- Monthly usage is charged download usage for the current UTC calendar month; reset is midnight UTC on the first day of the following month. All timestamps/month fields derive from one captured instant.
- `storageEnabled` means configured storage is enabled, not that network access or a future upload is guaranteed. No provider endpoint, bucket, key or identity is exposed.
- Single-use refers to the download authorization, not the shared file link. The recipient's download quota is independently enforced.
- The frontend may reject a known oversized batch or exhausted storage, but a snapshot reserves nothing. Upload/complete/download remain authoritative and may fail after successful preflight, including room/role, pending-limit, concurrent quota or configuration changes.
- Older implementations (404/405), malformed responses and read failures remain explicitly unverified. They do not imply unlimited quota or trigger a presign call. Direct-only transfers do not require this API.

Implementation tracking: issue #38. Java, Go and .NET implementations are developed together; C parity must be implemented and verified separately against its object-storage implementation before the cross-language milestone is marked complete.
