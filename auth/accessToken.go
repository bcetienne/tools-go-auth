package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gitlab.com/bcstudio1/tools/go-auth/lib"
	"gitlab.com/bcstudio1/tools/go-auth/model"
)

type AccessTokenService struct {
	config *lib.Config
}

type AccessTokenServiceInterface interface {
	CreateAccessToken(user *model.AuthUser) (string, error)
	VerifyAccessToken(token string) (*model.Claim, error)
}

func NewAccessTokenService(config *lib.Config) AccessTokenService {
	return AccessTokenService{
		config: config,
	}
}

func (at *AccessTokenService) CreateAccessToken(user *model.AuthUser) (string, error) {
	duration, err := time.ParseDuration(at.config.JWTExpiry)
	if err != nil {
		return "", err
	}

	claim := model.Claim{
		KeyType: "access",
		UserID:  user.UserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    at.config.Issuer,
			Subject:   user.Email,
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	return token.SignedString([]byte(at.config.JWTSecret))
}

func (at *AccessTokenService) VerifyAccessToken(token string) (*model.Claim, error) {
	t, err := jwt.ParseWithClaims(token, &model.Claim{}, func(token *jwt.Token) (any, error) {
		return []byte(at.config.JWTSecret), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		// Specific case if the token is expired (to check if refresh is possible)
		if errors.Is(err, jwt.ErrTokenExpired) {
			return t.Claims.(*model.Claim), jwt.ErrTokenExpired
		}
		return nil, err
	}

	if claim, ok := t.Claims.(*model.Claim); ok && t.Valid {
		return claim, nil
	}

	return nil, fmt.Errorf("invalid token claim")
}
