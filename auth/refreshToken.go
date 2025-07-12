package auth

import (
	"database/sql"

	"gitlab.com/bcstudio1/tools/go-auth/lib"
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
		CREATE TABLE refresh_token (
			refresh_token_id SERIAL PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at TIMESTAMPTZ,
			UNIQUE(token)
		);
		COMMENT ON TABLE refresh_token IS 'Refresh tokens for user authentication';
		CREATE INDEX idx_refresh_token_token ON refresh_token(token);
		CREATE INDEX idx_refresh_token_expires_at ON refresh_token(expires_at);
		`
		_, err = db.Exec(query)
		if err != nil {
			return nil, err
		}
	}

	return service, nil
}

func (rts *RefreshTokenService) CreateRefreshToken(userID int) (string, error) {
}

func (rts *RefreshTokenService) VerifyRefreshToken(token string) (int, error) {
}

func (rts *RefreshTokenService) RevokeRefreshToken(token string, userID int) error {
}

func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(userID int) error {
}

func (rts *RefreshTokenService) FlushRefreshTokens() error {
}
