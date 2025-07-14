package auth

import (
	"database/sql"
	"time"

	"gitlab.com/bcstudio1/tools/go-auth/lib"
	"gitlab.com/bcstudio1/tools/go-auth/model"
)

type RefreshTokenService struct {
	db     *sql.DB
	config *lib.Config
}

type RefreshTokenServiceInterface interface {
	CreateRefreshToken(userID int) (string, error)
	//VerifyRefreshToken(token string) (int, error)
	RevokeRefreshToken(token string, userID int) error
	RevokeAllUserRefreshTokens(userID int) error
	FlushRefreshTokens() error
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

	// Check if schema exists
	queryExists := `
	SELECT EXISTS (
		SELECT FROM information_schema.tables
		WHERE table_schema = 'go_auth'
	)
	`
	err := db.QueryRow(queryExists).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the schema if it does not exist
		_, err = db.Exec(`CREATE SCHEMA go_auth;`)
		if err != nil {
			return nil, err
		}
	}

	// Check if table exists
	queryExists = `
	SELECT EXISTS (
		SELECT FROM information_schema.tables
		WHERE table_schema = 'go_auth'
		AND table_name = 'refresh_token'
	)
	`
	err = db.QueryRow(queryExists).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Create the table if it does not exist
		query := `
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
		_, err = db.Exec(query)
		if err != nil {
			return nil, err
		}
	}

	return service, nil
}

// CreateRefreshToken creates a new refresh token for a user
func (rts *RefreshTokenService) CreateRefreshToken(userID int) (*model.RefreshToken, error) {
	query := `INSERT INTO go_auth.refresh_token (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING refresh_token_id`

	// Parse duration from configuration
	duration, err := time.ParseDuration(rts.config.RefreshTokenExpiry)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(duration)

	// Create a random token
	token, err := lib.GenerateRandomString(255)
	if err != nil {
		return nil, err
	}

	refreshToken := model.NewRefreshToken(userID, token, expiresAt)

	row := rts.db.QueryRow(query, userID, token, expiresAt)
	err = row.Scan(&refreshToken.RefreshTokenID)
	if err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

//func (rts *RefreshTokenService) VerifyRefreshToken(token string) (int, error) {
//	query := ``
//}

// RevokeRefreshToken revokes a refresh token for a user
func (rts *RefreshTokenService) RevokeRefreshToken(token string, userID int) error {
	query := `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND token = $2 AND revoked_at IS NULL`
	_, err := rts.db.Exec(query, userID, token)
	if err != nil {
		return err
	}
	return nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens not already revoked, for a user
func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(userID int) error {
	query := `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := rts.db.Exec(query, userID)
	if err != nil {
		return err
	}
	return nil
}

// FlushRefreshTokens deletes all refresh tokens
func (rts *RefreshTokenService) FlushRefreshTokens() error {
	query := `DELETE FROM go_auth.refresh_token`
	_, err := rts.db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

// FlushUserRefreshTokens deletes all refresh tokens for a user
func (rts *RefreshTokenService) FlushUserRefreshTokens(userID int) error {
	query := `DELETE FROM go_auth.refresh_token WHERE user_id = $1`
	_, err := rts.db.Exec(query, userID)
	if err != nil {
		return err
	}
	return nil
}
