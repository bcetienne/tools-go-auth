package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/bcetienne/tools-go-auth/lib"
	"github.com/bcetienne/tools-go-auth/model"
)

type RefreshTokenService struct {
	db     *sql.DB
	config *lib.Config
}

type RefreshTokenServiceInterface interface {
	CreateRefreshToken(userID int) (*model.RefreshToken, error)
	CreateRefreshTokenWithContext(ctx context.Context, userID int) (*model.RefreshToken, error)
	VerifyRefreshToken(token string) (*bool, error)
	VerifyRefreshTokenWithContext(ctx context.Context, token string) (*bool, error)
	RevokeRefreshToken(token string, userID int) error
	RevokeRefreshTokenWithContext(ctx context.Context, token string, userID int) error
	RevokeAllUserRefreshTokens(userID int) error
	RevokeAllUserRefreshTokensWithContext(ctx context.Context, userID int) error
	DeleteExpiredRefreshTokens() error
	DeleteExpiredRefreshTokensWithContext(ctx context.Context) error
	FlushRefreshTokens() error
	FlushRefreshTokensWithContext(ctx context.Context) error
}

type queryType string

const (
	schemaExists        queryType = "schemaExists"
	tableExists         queryType = "tableExists"
	schemaCreation      queryType = "schemaCreation"
	tableCreation       queryType = "tableCreation"
	createRefreshToken  queryType = "createRefreshToken"
	verifyToken         queryType = "verifyToken"
	revokeToken         queryType = "revokeToken"
	revokeAllTokens     queryType = "revokeAllTokens"
	revokeExpiredTokens queryType = "revokeExpiredTokens"
	flush               queryType = "flush"
	flushUserTokens     queryType = "flushUserTokens"
)

func getQuery(query queryType) string {
	switch query {
	case schemaExists:
		return `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'go_auth'
		)
		`
	case tableExists:
		return `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'go_auth'
			AND table_name = 'refresh_token'
		)
		`
	case schemaCreation:
		return `CREATE SCHEMA go_auth`
	case tableCreation:
		return `
		CREATE TABLE go_auth.refresh_token (
			refresh_token_id SERIAL PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at TIMESTAMPTZ,
			UNIQUE(token)
		);
		COMMENT ON TABLE go_auth.refresh_token IS 'Refresh tokens for user authentication';
		CREATE INDEX idx_refresh_token_token ON go_auth.refresh_token(token);
		CREATE INDEX idx_refresh_token_expires_at ON go_auth.refresh_token(expires_at);
		`
	case createRefreshToken:
		return `INSERT INTO go_auth.refresh_token (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING refresh_token_id`
	case verifyToken:
		return `SELECT EXISTS(SELECT refresh_token_id FROM go_auth.refresh_token WHERE token = $1 AND revoked_at IS NULL AND expires_at > NOW())`
	case revokeToken:
		return `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND token = $2 AND revoked_at IS NULL`
	case revokeAllTokens:
		return `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	case revokeExpiredTokens:
		return `DELETE FROM go_auth.refresh_token WHERE expires_at < NOW() OR (revoked_at IS NOT NULL AND revoked_at < NOW())`
	case flush:
		return `DELETE FROM go_auth.refresh_token`
	case flushUserTokens:
		return `DELETE FROM go_auth.refresh_token WHERE user_id = $1`
	}

	return ""
}

func newToken(config *lib.Config, userID int) (*model.RefreshToken, *string, *time.Time, error) {
	// Parse duration from configuration
	duration, err := time.ParseDuration(config.RefreshTokenExpiry)
	if err != nil {
		return nil, nil, nil, err
	}
	expiresAt := time.Now().Add(duration)

	// Create a random token
	token, err := lib.GenerateRandomString(255)
	if err != nil {
		return nil, nil, nil, err
	}

	return model.NewRefreshToken(userID, token, expiresAt), &token, &expiresAt, nil
}

// NewRefreshTokenService initializes the refresh token management service.
// This function checks for the existence of the required schema and table in the PostgreSQL database.
// If the schema or table does not exist, they are created automatically.
//
// Parameters:
//   - db: pointer to the SQL database connection
//   - config: application configuration
//
// Returns:
//   - *RefreshTokenService: instance of the initialized service
//   - error: any error encountered during initialization
func NewRefreshTokenService(db *sql.DB, config *lib.Config) (*RefreshTokenService, error) {
	service := &RefreshTokenService{
		db:     db,
		config: config,
	}

	var exists bool

	// Prepare transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Check if schema exists
	err = tx.QueryRow(getQuery(schemaExists)).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the schema if it does not exist
		_, err = tx.Exec(getQuery(schemaCreation))
		if err != nil {
			return nil, err
		}
	}

	// Check if table exists
	err = tx.QueryRow(getQuery(tableExists)).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the table if it does not exist
		_, err = tx.Exec(getQuery(tableCreation))
		if err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return service, nil
}

func NewRefreshTokenServiceWithContext(ctx context.Context, db *sql.DB, config *lib.Config) (*RefreshTokenService, error) {
	service := &RefreshTokenService{
		db:     db,
		config: config,
	}

	var exists bool

	// Prepare transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Check if schema exists
	err = tx.QueryRowContext(ctx, getQuery(schemaExists)).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the schema if it does not exist
		_, err = tx.ExecContext(ctx, getQuery(schemaCreation))
		if err != nil {
			return nil, err
		}
	}

	// Check if table exists
	err = tx.QueryRowContext(ctx, getQuery(tableExists)).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the table if it does not exist
		_, err = tx.ExecContext(ctx, getQuery(tableCreation))
		if err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return service, nil
}

// CreateRefreshToken creates a new refresh token for a user
func (rts *RefreshTokenService) CreateRefreshToken(userID int) (*model.RefreshToken, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	refreshToken, token, expiresAt, err := newToken(rts.config, userID)
	if err != nil {
		return nil, err
	}

	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRow(getQuery(createRefreshToken), userID, token, expiresAt)
	err = row.Scan(&refreshToken.RefreshTokenID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (rts *RefreshTokenService) CreateRefreshTokenWithContext(ctx context.Context, userID int) (*model.RefreshToken, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	refreshToken, token, expiresAt, err := newToken(rts.config, userID)
	if err != nil {
		return nil, err
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, getQuery(createRefreshToken), userID, token, expiresAt)
	err = row.Scan(&refreshToken.RefreshTokenID)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return refreshToken, nil
}

// VerifyRefreshToken checks if a given refresh token is valid and not revoked.
func (rts *RefreshTokenService) VerifyRefreshToken(token string) (*bool, error) {
	var exists bool
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row := tx.QueryRow(getQuery(verifyToken), token)
	err = row.Scan(&exists)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &exists, nil
}

func (rts *RefreshTokenService) VerifyRefreshTokenWithContext(ctx context.Context, token string) (*bool, error) {
	var exists bool
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, getQuery(verifyToken), token)
	err = row.Scan(&exists)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &exists, nil
}

// RevokeRefreshToken revokes a refresh token for a user
func (rts *RefreshTokenService) RevokeRefreshToken(token string, userID int) error {
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(getQuery(revokeToken), userID, token)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) RevokeRefreshTokenWithContext(ctx context.Context, token string, userID int) error {
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, getQuery(revokeToken), userID, token)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens not already revoked, for a user
func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(userID int) error {
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(getQuery(revokeAllTokens), userID)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) RevokeAllUserRefreshTokensWithContext(ctx context.Context, userID int) error {
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, getQuery(revokeAllTokens), userID)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) DeleteExpiredRefreshTokens() error {
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(getQuery(revokeExpiredTokens))
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) DeleteExpiredRefreshTokensWithContext(ctx context.Context) error {
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, getQuery(revokeExpiredTokens))
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

// FlushRefreshTokens deletes all refresh tokens
func (rts *RefreshTokenService) FlushRefreshTokens() error {
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(getQuery(flush))
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) FlushRefreshTokensWithContext(ctx context.Context) error {
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, getQuery(flush))
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

// FlushUserRefreshTokens deletes all refresh tokens for a user
func (rts *RefreshTokenService) FlushUserRefreshTokens(userID int) error {
	// Prepare transaction
	tx, err := rts.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(getQuery(flushUserTokens), userID)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (rts *RefreshTokenService) FlushUserRefreshTokensWithContext(ctx context.Context, userID int) error {
	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, getQuery(flushUserTokens), userID)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}
