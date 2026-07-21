package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (db *DB) ManagementEmailExists(ctx context.Context, email string) (bool, error) {
	var count int
	err := db.sql.QueryRowContext(ctx, db.rebind(
		`SELECT COUNT(*) FROM tunnel_management_user_email WHERE LOWER(email) = LOWER(?)`), email).Scan(&count)
	return count > 0, err
}

func (db *DB) FindRegistrationChallengeByID(
	ctx context.Context, registrationID string,
) (*ManagementRegistrationChallenge, error) {
	row := db.sql.QueryRowContext(ctx, db.rebind(`SELECT registration_id, username, email,
		password_hash, code_hash, attempts_remaining, expires_at, resend_available_at, created_at, updated_at
		FROM tunnel_management_registration_challenge WHERE registration_id = ?`), registrationID)
	challenge, err := scanRegistrationChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (db *DB) FindRegistrationChallengeByUsernameOrEmail(
	ctx context.Context, username, email string,
) (*ManagementRegistrationChallenge, error) {
	row := db.sql.QueryRowContext(ctx, db.rebind(`SELECT registration_id, username, email,
		password_hash, code_hash, attempts_remaining, expires_at, resend_available_at, created_at, updated_at
		FROM tunnel_management_registration_challenge
		WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1`), username, email)
	challenge, err := scanRegistrationChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (db *DB) InsertRegistrationChallenge(ctx context.Context, challenge ManagementRegistrationChallenge) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_management_registration_challenge
		(registration_id, username, email, password_hash, code_hash, attempts_remaining,
		 expires_at, resend_available_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		challenge.RegistrationID, challenge.Username, challenge.Email, challenge.PasswordHash,
		challenge.CodeHash, challenge.AttemptsRemaining, formatTime(challenge.ExpiresAt),
		formatTime(challenge.ResendAvailableAt), formatTime(challenge.CreatedAt), formatTime(challenge.UpdatedAt))
	return err
}

func (db *DB) UpdateRegistrationChallengeAttempts(
	ctx context.Context, registrationID string, attempts int, updatedAt time.Time,
) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`UPDATE tunnel_management_registration_challenge
		SET attempts_remaining = ?, updated_at = ? WHERE registration_id = ?`),
		attempts, formatTime(updatedAt), registrationID)
	return err
}

func (db *DB) DeleteRegistrationChallenge(ctx context.Context, registrationID string) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(
		`DELETE FROM tunnel_management_registration_challenge WHERE registration_id = ?`), registrationID)
	return err
}

func (db *DB) DeleteExpiredRegistrationChallenges(ctx context.Context, expiresBefore time.Time) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(
		`DELETE FROM tunnel_management_registration_challenge WHERE expires_at < ?`), formatTime(expiresBefore))
	return err
}

func (db *DB) CompleteVerifiedRegistration(
	ctx context.Context,
	challenge ManagementRegistrationChallenge,
	user ManagementUser,
	userEmail ManagementUserEmail,
) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_management_user
		(username, tenant_id, password_hash, role, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`), user.Username, defaultTenant(user.TenantID), user.PasswordHash,
		normalizeManagementRole(user.Role), boolToInt(user.Enabled), formatTime(user.CreatedAt),
		formatTime(user.UpdatedAt)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_management_user_email
		(username, email, verified_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`),
		userEmail.Username, userEmail.Email, formatTime(userEmail.VerifiedAt),
		formatTime(userEmail.CreatedAt), formatTime(userEmail.UpdatedAt)); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_management_registration_challenge
		WHERE registration_id = ? AND code_hash = ?`), challenge.RegistrationID, challenge.CodeHash)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return fmt.Errorf("registration challenge changed before completion")
	}
	return tx.Commit()
}

type registrationChallengeScanner interface {
	Scan(dest ...any) error
}

func scanRegistrationChallenge(scanner registrationChallengeScanner) (ManagementRegistrationChallenge, error) {
	var challenge ManagementRegistrationChallenge
	var expiresAt, resendAt, createdAt, updatedAt string
	err := scanner.Scan(&challenge.RegistrationID, &challenge.Username, &challenge.Email,
		&challenge.PasswordHash, &challenge.CodeHash, &challenge.AttemptsRemaining,
		&expiresAt, &resendAt, &createdAt, &updatedAt)
	if err != nil {
		return ManagementRegistrationChallenge{}, err
	}
	challenge.ExpiresAt = parseTime(expiresAt)
	challenge.ResendAvailableAt = parseTime(resendAt)
	challenge.CreatedAt = parseTime(createdAt)
	challenge.UpdatedAt = parseTime(updatedAt)
	return challenge, nil
}
