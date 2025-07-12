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
	VerifyRefreshToken(token string) (int, error)
	RevokeRefreshToken(token string, userID int) error
	RevokeAllUserRefreshTokens(userID int) error
	FlushRefreshTokens() error
}

func NewRefreshTokenService(db *sql.DB, config *lib.Config) (*RefreshTokenService, error) {
	service := &RefreshTokenService{
		db:     db,
		config: config,
	}

	var exists bool

	// Does schema exists ?
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
		// Create the schema
		_, err = db.Exec(`CREATE SCHEMA go_auth;`)
		if err != nil {
			return nil, err
		}
	}

	// Does table exists ?
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
		// Create the table
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

func (rts *RefreshTokenService) VerifyRefreshToken(token string) (int, error) {
	query := ``
}

func (rts *RefreshTokenService) RevokeRefreshToken(token string, userID int) error {
	query := `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND token = $2 AND revoked_at IS NULL`
}

func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(userID int) error {
	query := `UPDATE go_auth.refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
}

func (rts *RefreshTokenService) FlushRefreshTokens() error {
	query := `DELETE FROM go_auth.refresh_token`
}

func (rts *RefreshTokenService) FlushUserRefreshTokens(userID int) error {
	query := `DELETE FROM go_auth.refresh_token WHERE user_id = $1`
}
