package transfer

import (
	"context"
	"fmt"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestCapabilitiesAccountIsolationExpiryAndReadOnly(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "capabilities.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Default().ObjectStorage
	cfg.Provider, cfg.Endpoint, cfg.Region, cfg.Bucket, cfg.AccessKeyID, cfg.AccessKeySecret = "aliyun-oss", "oss.example.com", "cn-hangzhou", "private", "key", "secret"
	cfg.PerUserStorageQuotaBytes, cfg.PerUserMonthlyDownloadQuotaBytes = 20, 10
	s := NewService(db, cfg, config.PublicTransferConfig{})
	s.storage.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("capabilities must not access object storage")
		return nil, nil
	})}
	ctx, now := context.Background(), time.Now().UTC()
	tenant, user := "default", "alice"
	for i, row := range []struct {
		tenant, user, status string
		size                 int64
		expired              bool
	}{
		{tenant, user, StatusPending, 10, false}, {tenant, user, StatusUploaded, 20, false},
		{tenant, user, StatusPending, 100, true}, {tenant, user, StatusUploaded, 100, true},
		{"other", user, StatusPending, 100, false}, {tenant, "bob", StatusUploaded, 100, false},
	} {
		expiry := now.Add(time.Hour)
		if row.expired {
			expiry = now.Add(-time.Hour)
		}
		// Include the admin scope: quota is account-wide, not only this room or public uploads.
		item := store.TransferAttachment{ID: int64(i + 1), TenantID: &row.tenant, OwnerUsername: &row.user,
			Scope: ScopeAdminClientMessage, ObjectKey: fmt.Sprint(i), FileName: "test.bin", MimeType: "application/octet-stream",
			SizeBytes: row.size, Status: row.status, CreatedAt: now, UpdatedAt: now, UploadExpiresAt: expiry, ExpiresAt: expiry}
		if err := db.InsertTransferAttachment(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range []struct {
		tenant, user, month string
		size                int64
	}{
		{tenant, user, now.Format("2006-01"), 14}, {tenant, user, now.AddDate(0, -1, 0).Format("2006-01"), 100},
		{"other", user, now.Format("2006-01"), 100}, {tenant, "bob", now.Format("2006-01"), 100},
	} {
		id := int64(100 + i)
		hash := fmt.Sprint(id)
		if err := db.InsertTransferDownloadGrant(ctx, store.TransferAttachmentDownloadGrant{ID: id, TokenHash: hash,
			TenantID: row.tenant, Username: row.user, AttachmentID: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if ok, err := db.ConsumeTransferDownloadGrantAndInsertUsage(ctx, id, hash, now, id, row.tenant, row.user, 1, row.size, row.month); err != nil || !ok {
			t.Fatalf("seed usage %v %v", ok, err)
		}
	}
	for range 2 {
		v, err := s.Capabilities(ctx, tenant, user)
		if err != nil {
			t.Fatal(err)
		}
		if !v.StorageEnabled || v.StorageUsedBytes != 30 || v.StorageRemainingBytes != 0 || v.MonthlyDownloadUsedBytes != 14 || v.MonthlyDownloadRemainingBytes != 0 {
			t.Fatalf("wrong snapshot: %+v", v)
		}
		if v.DownloadUsageMonth != v.CheckedAt.Format("2006-01") || v.DownloadResetsAt.Day() != 1 || !v.DownloadResetsAt.After(v.CheckedAt) || !v.DownloadGrantSingleUse {
			t.Fatalf("wrong period: %+v", v)
		}
	}
	if len(s.rateByIP) != 0 {
		t.Fatal("read consumed presign rate limit")
	}
}

func TestCapabilitiesDisabledDefaultsAndReadFailure(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "capabilities.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(db, config.ObjectStorageConfig{}, config.PublicTransferConfig{})
	v, err := s.Capabilities(context.Background(), "default", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if v.StorageEnabled || v.StorageQuotaBytes != defaultPerUserQuotaBytes || v.MonthlyDownloadQuotaBytes != defaultPerUserQuotaBytes || v.RetentionHours != 1 || v.MaxAttachmentBytes != 0 {
		t.Fatalf("wrong defaults: %+v", v)
	}
	db.Close()
	if _, err := s.Capabilities(context.Background(), "default", "alice"); err == nil {
		t.Fatal("read failure became zero usage")
	}
	if _, err := s.Capabilities(context.Background(), "", "alice"); err == nil {
		t.Fatal("missing identity accepted")
	}
}
