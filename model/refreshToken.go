package model

import "time"

type RefreshToken struct {
	RefreshTokenID int       `json:"refresh_token_id"`
	UserID         int       `json:"user_id"`
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
}

func NewRefreshToken(userID int, token string, expiresAt time.Time) RefreshToken {
	return RefreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
}
