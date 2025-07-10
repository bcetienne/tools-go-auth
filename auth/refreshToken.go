package auth

import "gitlab.com/bcstudio1/tools/go-auth/lib"

type RefreshTokenService struct {
	config *lib.Config
}

type RefreshTokenServiceInterface interface {
	CreateRefreshToken(userID int) (string, error)
	VerifyRefreshToken(token string) (int, error)
	RevokeRefreshToken(token string, userID int) error
	RevokeAllUserRefreshTokens(userID int) error
	FlushRefreshTokens() error
}

func NewRefreshTokenService(config *lib.Config) RefreshTokenService {
	return RefreshTokenService{
		config: config,
	}
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
