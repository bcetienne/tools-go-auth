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
	CreateRefreshToken(ctx context.Context, userID int) (*model.RefreshToken, error)
	VerifyRefreshToken(ctx context.Context, token string) (*bool, error)
	RevokeRefreshToken(ctx context.Context, token string, userID int) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID int) error
	DeleteExpiredRefreshTokens(ctx context.Context) error
	FlushRefreshTokens(ctx context.Context) error
	FlushUserRefreshTokens(ctx context.Context, userID int) error
}

type queryType string

const (
	tokenMaxLength      int       = 255
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
		CREATE INDEX idx_refresh_token_user_id ON go_auth.refresh_token(user_id);
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

func isIncomingTokenValid(token string) error {
	if len(token) == 0 {
		return errors.New("empty token")
	}
	if len(token) > tokenMaxLength {
		return errors.New("token too long")
	}
	return nil
}

func (rts *RefreshTokenService) newRefreshToken(userID int) (*model.RefreshToken, error) {
	// Parse duration from configuration
	duration, err := time.ParseDuration(rts.config.RefreshTokenExpiry)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(duration)

	// Create a random token
	token, err := lib.GenerateRandomString(tokenMaxLength)
	if err != nil {
		return nil, err
	}

	return model.NewRefreshToken(userID, token, expiresAt), nil
}

// NewRefreshTokenService initializes the refresh token management service.
// This function checks for the existence of the required schema and table in the PostgreSQL database.
// If the schema or table does not exist, they are created automatically.
//
// Parameters:
//   - ctx: context for the operation
//   - db: pointer to the SQL database connection
//   - config: application configuration
//
// Returns:
//   - *RefreshTokenService: instance of the initialized service
//   - error: any error encountered during initialization
func NewRefreshTokenService(ctx context.Context, db *sql.DB, config *lib.Config) (*RefreshTokenService, error) {
	if ctx == nil {
		ctx = context.Background()
	}

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

// CreateRefreshToken creates a new refresh token for a user
func (rts *RefreshTokenService) CreateRefreshToken(ctx context.Context, userID int) (*model.RefreshToken, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	refreshToken, err := rts.newRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, getQuery(createRefreshToken), refreshToken.UserID, refreshToken.Token, refreshToken.ExpiresAt)
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
func (rts *RefreshTokenService) VerifyRefreshToken(ctx context.Context, token string) (*bool, error) {
	if err := isIncomingTokenValid(token); err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	var exists bool
	row := rts.db.QueryRowContext(ctx, getQuery(verifyToken), token)
	if err := row.Scan(&exists); err != nil {
		return nil, err
	}
	return &exists, nil
}

// RevokeRefreshToken revokes a refresh token for a user
func (rts *RefreshTokenService) RevokeRefreshToken(ctx context.Context, token string, userID int) error {
	if err := isIncomingTokenValid(token); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, getQuery(revokeToken), userID, token)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("token not found or already revoked")
	}

	return tx.Commit()
}

// RevokeAllUserRefreshTokens revokes all refresh tokens not already revoked, for a user
func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, getQuery(revokeAllTokens), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (rts *RefreshTokenService) DeleteExpiredRefreshTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, getQuery(revokeExpiredTokens))
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

// FlushRefreshTokens deletes all refresh tokens
func (rts *RefreshTokenService) FlushRefreshTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, getQuery(flush))
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}
	return tx.Commit()
}

// FlushUserRefreshTokens deletes all refresh tokens for a user
func (rts *RefreshTokenService) FlushUserRefreshTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, getQuery(flushUserTokens), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}
	return tx.Commit()
}
