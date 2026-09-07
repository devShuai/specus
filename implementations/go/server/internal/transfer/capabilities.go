package transfer

import (
	"context"
	"time"
)

type Capabilities struct {
	SchemaVersion                 int       `json:"schemaVersion"`
	CheckedAt                     time.Time `json:"checkedAt"`
	StorageEnabled                bool      `json:"storageEnabled"`
	MaxAttachmentBytes            int64     `json:"maxAttachmentBytes"`
	RetentionHours                int64     `json:"retentionHours"`
	StorageQuotaBytes             int64     `json:"storageQuotaBytes"`
	StorageUsedBytes              int64     `json:"storageUsedBytes"`
	StorageRemainingBytes         int64     `json:"storageRemainingBytes"`
	MonthlyDownloadQuotaBytes     int64     `json:"monthlyDownloadQuotaBytes"`
	MonthlyDownloadUsedBytes      int64     `json:"monthlyDownloadUsedBytes"`
	MonthlyDownloadRemainingBytes int64     `json:"monthlyDownloadRemainingBytes"`
	DownloadUsageMonth            string    `json:"downloadUsageMonth"`
	DownloadResetsAt              time.Time `json:"downloadResetsAt"`
	DownloadGrantSingleUse        bool      `json:"downloadGrantSingleUse"`
}

// Capabilities reads the current account only. It never signs URLs or reserves quota.
func (s *Service) Capabilities(ctx context.Context, tenantID, username string) (Capabilities, error) {
	tenantID, username, err := normalizeAccount(tenantID, username)
	if err != nil {
		return Capabilities{}, err
	}
	lock := s.quotaLock(tenantID, username)
	lock.Lock()
	defer lock.Unlock()
	now := time.Now().UTC()
	used, err := s.db.SumActiveTransferStorageBytes(ctx, tenantID, username, -1, now)
	if err != nil {
		return Capabilities{}, internalError(err)
	}
	month := now.Format("2006-01")
	downloaded, err := s.db.SumTransferDownloadUsageBytes(ctx, tenantID, username, month)
	if err != nil {
		return Capabilities{}, internalError(err)
	}
	used, downloaded = max(0, used), max(0, downloaded)
	storageLimit, downloadLimit := s.objectCfg.PerUserStorageQuotaBytes, s.objectCfg.PerUserMonthlyDownloadQuotaBytes
	if storageLimit <= 0 {
		storageLimit = defaultPerUserQuotaBytes
	}
	if downloadLimit <= 0 {
		downloadLimit = defaultPerUserQuotaBytes
	}
	return Capabilities{
		SchemaVersion: 1, CheckedAt: now, StorageEnabled: s.storage.Enabled(),
		MaxAttachmentBytes: max(0, s.objectCfg.MaxAttachmentBytes), RetentionHours: max(1, s.objectCfg.RetentionHours),
		StorageQuotaBytes: storageLimit, StorageUsedBytes: used, StorageRemainingBytes: max(0, storageLimit-used),
		MonthlyDownloadQuotaBytes: downloadLimit, MonthlyDownloadUsedBytes: downloaded,
		MonthlyDownloadRemainingBytes: max(0, downloadLimit-downloaded), DownloadUsageMonth: month,
		DownloadResetsAt: time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC), DownloadGrantSingleUse: true,
	}, nil
}
