package store

import (
	"database/sql"
	"testing"
)

func TestDatabaseBooleanScan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{name: "boolean", value: true, want: true},
		{name: "integer zero", value: int64(0), want: false},
		{name: "integer one", value: int64(1), want: true},
		{name: "mysql bit zero", value: []byte{0}, want: false},
		{name: "mysql bit one", value: []byte{1}, want: true},
		{name: "text zero", value: []byte("0"), want: false},
		{name: "text one", value: "1", want: true},
		{name: "text true", value: "true", want: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var value databaseBoolean
			if err := value.Scan(tt.value); err != nil {
				t.Fatalf("Scan(%v): %v", tt.value, err)
			}
			if got := bool(value); got != tt.want {
				t.Fatalf("Scan(%v) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestDatabaseBooleanRejectsInvalidValue(t *testing.T) {
	t.Parallel()
	var value databaseBoolean
	if err := value.Scan([]byte{2}); err == nil {
		t.Fatal("Scan invalid BIT value succeeded")
	}
}

func TestScanManagementUserAcceptsMySQLBit(t *testing.T) {
	t.Parallel()
	user, err := scanManagementUser(managementUserBitScanner{})
	if err != nil {
		t.Fatalf("scanManagementUser: %v", err)
	}
	if !user.Enabled || user.Username != "test-user" || user.TenantID != "default" {
		t.Fatalf("unexpected management user: %+v", user)
	}
}

type managementUserBitScanner struct{}

func (managementUserBitScanner) Scan(dest ...any) error {
	*dest[0].(*string) = "test-user"
	*dest[1].(*string) = "default"
	*dest[2].(*string) = "hash"
	*dest[3].(*string) = ManagementRoleUser
	if err := dest[4].(sql.Scanner).Scan([]byte{1}); err != nil {
		return err
	}
	*dest[5].(*string) = "2026-07-23T00:00:00.0000000Z"
	*dest[6].(*string) = "2026-07-23T00:00:00.0000000Z"
	return nil
}
