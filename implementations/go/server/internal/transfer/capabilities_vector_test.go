package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Replays protocol/test-vectors/transfer-capabilities-v1.json: the rows of each case go into the
// SQLite store through the same queries the upload and download paths use, the service clock is
// fixed at the case instant, and the snapshot must match the vector field by field.

type capabilitiesVector struct {
	Cases []struct {
		Name    string `json:"name"`
		Now     string `json:"now"`
		Account struct {
			TenantID string `json:"tenantId"`
			Username string `json:"username"`
		} `json:"account"`
		Config struct {
			StorageEnabled            bool  `json:"storageEnabled"`
			MaxAttachmentBytes        int64 `json:"maxAttachmentBytes"`
			RetentionHours            int64 `json:"retentionHours"`
			StorageQuotaBytes         int64 `json:"storageQuotaBytes"`
			MonthlyDownloadQuotaBytes int64 `json:"monthlyDownloadQuotaBytes"`
		} `json:"config"`
		Attachments []struct {
			TenantID        string `json:"tenantId"`
			Username        string `json:"username"`
			Scope           string `json:"scope"`
			Status          string `json:"status"`
			SizeBytes       int64  `json:"sizeBytes"`
			UploadExpiresAt string `json:"uploadExpiresAt"`
			ExpiresAt       string `json:"expiresAt"`
		} `json:"attachments"`
		DownloadUsage []struct {
			TenantID   string `json:"tenantId"`
			Username   string `json:"username"`
			UsageMonth string `json:"usageMonth"`
			SizeBytes  int64  `json:"sizeBytes"`
		} `json:"downloadUsage"`
		Expect struct {
			SchemaVersion                 int    `json:"schemaVersion"`
			CheckedAt                     string `json:"checkedAt"`
			StorageEnabled                bool   `json:"storageEnabled"`
			MaxAttachmentBytes            int64  `json:"maxAttachmentBytes"`
			RetentionHours                int64  `json:"retentionHours"`
			StorageQuotaBytes             int64  `json:"storageQuotaBytes"`
			StorageUsedBytes              int64  `json:"storageUsedBytes"`
			StorageRemainingBytes         int64  `json:"storageRemainingBytes"`
			MonthlyDownloadQuotaBytes     int64  `json:"monthlyDownloadQuotaBytes"`
			MonthlyDownloadUsedBytes      int64  `json:"monthlyDownloadUsedBytes"`
			MonthlyDownloadRemainingBytes int64  `json:"monthlyDownloadRemainingBytes"`
			DownloadUsageMonth            string `json:"downloadUsageMonth"`
			DownloadResetsAt              string `json:"downloadResetsAt"`
			DownloadGrantSingleUse        bool   `json:"downloadGrantSingleUse"`
		} `json:"expect"`
	} `json:"cases"`
}

// The vector's two scopes stand for two distinct attachment scopes: usage is account-wide.
var capabilitiesVectorScopes = map[string]string{"ROOM": ScopePublicTransfer, "LINK": ScopeAdminClientMessage}

func loadCapabilitiesVector(t *testing.T) capabilitiesVector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "transfer-capabilities-v1.json"))
		if err == nil {
			var vector capabilitiesVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			return vector
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("cannot locate transfer-capabilities-v1.json")
	return capabilitiesVector{}
}

func vectorInstant(t *testing.T, text string) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339, text)
	if err != nil {
		t.Fatalf("instant %q: %v", text, err)
	}
	return value
}

func TestCapabilitiesMatchTheSharedVector(t *testing.T) {
	vector := loadCapabilitiesVector(t)
	if len(vector.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, c := range vector.Cases {
		t.Run(c.Name, func(t *testing.T) {
			db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "capabilities.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx, now := context.Background(), vectorInstant(t, c.Now)
			for i, row := range c.Attachments {
				scope, ok := capabilitiesVectorScopes[row.Scope]
				if !ok {
					t.Fatalf("unknown scope %q", row.Scope)
				}
				tenant, owner := row.TenantID, row.Username
				item := store.TransferAttachment{ID: int64(i + 1), TenantID: &tenant, OwnerUsername: &owner,
					Scope: scope, ObjectKey: fmt.Sprintf("vector/%d", i+1), FileName: "vector.bin",
					MimeType: "application/octet-stream", SizeBytes: row.SizeBytes, Status: row.Status,
					CreatedAt: now, UpdatedAt: now, UploadExpiresAt: vectorInstant(t, row.UploadExpiresAt),
					ExpiresAt: vectorInstant(t, row.ExpiresAt)}
				if err := db.InsertTransferAttachment(ctx, item); err != nil {
					t.Fatal(err)
				}
			}
			// Download usage is only ever written when a grant is consumed, so seed it the same way.
			for i, row := range c.DownloadUsage {
				id := int64(1000 + i)
				hash := fmt.Sprintf("vector-grant-%d", id)
				if err := db.InsertTransferDownloadGrant(ctx, store.TransferAttachmentDownloadGrant{ID: id, TokenHash: hash,
					TenantID: row.TenantID, Username: row.Username, AttachmentID: 1, CreatedAt: now,
					ExpiresAt: now.Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
				if ok, err := db.ConsumeTransferDownloadGrantAndInsertUsage(ctx, id, hash, now, id, row.TenantID,
					row.Username, 1, row.SizeBytes, row.UsageMonth); err != nil || !ok {
					t.Fatalf("seed usage %v %v", ok, err)
				}
			}
			cfg := config.Default().ObjectStorage
			if c.Config.StorageEnabled {
				cfg.Provider, cfg.Endpoint, cfg.Region, cfg.Bucket = "aliyun-oss", "oss.example.com", "cn-hangzhou", "private"
				cfg.AccessKeyID, cfg.AccessKeySecret = "key", "secret"
			} else {
				cfg.Provider = ""
			}
			cfg.MaxAttachmentBytes, cfg.RetentionHours = c.Config.MaxAttachmentBytes, c.Config.RetentionHours
			cfg.PerUserStorageQuotaBytes = c.Config.StorageQuotaBytes
			cfg.PerUserMonthlyDownloadQuotaBytes = c.Config.MonthlyDownloadQuotaBytes
			s := NewService(db, cfg, config.PublicTransferConfig{})
			s.now = func() time.Time { return now }

			v, err := s.Capabilities(ctx, c.Account.TenantID, c.Account.Username)
			if err != nil {
				t.Fatal(err)
			}
			want := c.Expect
			if !v.CheckedAt.Equal(vectorInstant(t, want.CheckedAt)) {
				t.Errorf("checkedAt = %s, want %s", v.CheckedAt, want.CheckedAt)
			}
			if !v.DownloadResetsAt.Equal(vectorInstant(t, want.DownloadResetsAt)) {
				t.Errorf("downloadResetsAt = %s, want %s", v.DownloadResetsAt, want.DownloadResetsAt)
			}
			for _, field := range []struct {
				name      string
				got, want any
			}{
				{"schemaVersion", v.SchemaVersion, want.SchemaVersion},
				{"storageEnabled", v.StorageEnabled, want.StorageEnabled},
				{"maxAttachmentBytes", v.MaxAttachmentBytes, want.MaxAttachmentBytes},
				{"retentionHours", v.RetentionHours, want.RetentionHours},
				{"storageQuotaBytes", v.StorageQuotaBytes, want.StorageQuotaBytes},
				{"storageUsedBytes", v.StorageUsedBytes, want.StorageUsedBytes},
				{"storageRemainingBytes", v.StorageRemainingBytes, want.StorageRemainingBytes},
				{"monthlyDownloadQuotaBytes", v.MonthlyDownloadQuotaBytes, want.MonthlyDownloadQuotaBytes},
				{"monthlyDownloadUsedBytes", v.MonthlyDownloadUsedBytes, want.MonthlyDownloadUsedBytes},
				{"monthlyDownloadRemainingBytes", v.MonthlyDownloadRemainingBytes, want.MonthlyDownloadRemainingBytes},
				{"downloadUsageMonth", v.DownloadUsageMonth, want.DownloadUsageMonth},
				{"downloadGrantSingleUse", v.DownloadGrantSingleUse, want.DownloadGrantSingleUse},
			} {
				if field.got != field.want {
					t.Errorf("%s = %v, want %v", field.name, field.got, field.want)
				}
			}
		})
	}
}
