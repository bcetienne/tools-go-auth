package auth

import (
	"gitlab.com/bcstudio1/tools/go-auth/lib"
	"gitlab.com/bcstudio1/tools/go-auth/model"
	"testing"

	"gitlab.com/bcstudio1/tools/go-auth/auth"
)

func Test_Auth_AccessToken_CreateAccessToken_TableDriven(t *testing.T) {
	tests := []struct {
		testName      string
		expectSuccess bool
		jwtExpiry     string
	}{
		{
			testName:      "Success",
			expectSuccess: true,
			jwtExpiry:     "12h",
		},
		{
			testName:      "Fail - No duration",
			expectSuccess: false,
			jwtExpiry:     "",
		},
		{
			testName:      "Fail - Negative duration",
			expectSuccess: false,
			jwtExpiry:     "-12h",
		},
	}

	user := model.AuthUser{
		UserID:   1,
		UserUUID: "123-123-123",
		Email:    "user@mail.com",
	}
	config := lib.Config{
		Issuer:             "test_auth.com",
		JWTSecret:          "rand0mString_",
		RefreshTokenExpiry: "12h",
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			config.JWTExpiry = tt.jwtExpiry
			accessTokenService := auth.NewAccessTokenService(&config)
			at, err := accessTokenService.CreateAccessToken(&user)
			if err != nil {
				if tt.expectSuccess {
					t.Fatalf("The test expect no error, got : %v", err)
				}
			}
			if len(at) != 312 && tt.expectSuccess {
				t.Fatalf("The token should have a length of 312, got %d", len(at))
			}
		})
	}
}
