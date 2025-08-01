# Go Auth Package

A comprehensive authentication utility package for Go applications, providing secure password validation, email validation, JWT token management, and cryptographic utilities.

## Features

### 🔐 Password Security
- **Secure Hashing**: Bcrypt with configurable cost factor (default: 14)
- **Comprehensive Validation**: Uppercase, lowercase, digits, special characters
- **Configurable Requirements**: Minimum length (minimum 8 chars), blacklisted words
- **Built-in Protection**: Prevents weak passwords and common attack vectors

### 📧 Email Validation
- **RFC-Compliant**: Standard email format validation
- **Performance Optimized**: Pre-compiled regex patterns
- **Simple API**: Single function validation

### 🎫 JWT Token Management
- **Access Tokens**: Short-lived tokens for API authentication
- **Refresh Tokens**: Long-lived tokens with PostgreSQL database persistence
- **Secure Generation**: Uses HS256 signing with configurable secrets
- **Token Verification**: Built-in validation with proper error handling
- **Context Support**: All refresh token operations support context for better control

### 🎲 Cryptographic Utilities
- **Secure Random Strings**: Uses `crypto/rand` for token generation
- **Alphanumeric + Hyphen**: Safe character set for URLs and tokens (255 char max)
- **Error Handling**: Proper error propagation for crypto failures

## Installation

```bash
go get github.com/bcetienne/tools-go-auth
```

## Configuration

Create a configuration object with your settings:

```go
config := lib.NewConfig(
    "your-app.com",           // Issuer
    "your-secure-jwt-secret", // JWT Secret
    "15m",                    // Access token expiry
    "7d",                     // Refresh token expiry
)
```

## Quick Start

### Password Hashing

```go
import "github.com/bcetienne/tools-go-auth/lib"

// Create hasher
hasher := lib.NewPasswordHash()

// Hash password
hash, err := hasher.Hash("MySecurePassword123!")
if err != nil {
    log.Fatal(err)
}

// Verify password
isValid := hasher.CheckHash("MySecurePassword123!", hash)
fmt.Println("Password valid:", isValid) // true
```

### Password Validation

```go
import "github.com/bcetienne/tools-go-auth/validation"

// Create validator with defaults (min length: 8)
validator := validation.NewPasswordValidation()

// Customize requirements
validator.SetMinLength(12) // Won't go below 8 for security
validator.SetUnauthorizedWords([]string{"password", "admin", "123456"})

// Validate password strength
isStrong := validator.IsPasswordStrengthEnough("MyStrongP@ssw0rd!")
fmt.Println("Password strong:", isStrong) // true

// Check individual requirements
hasUpper := validator.PasswordContainsUppercase("test")
hasDigit := validator.PasswordContainsDigit("test123")
hasMinLength := validator.PasswordHasMinLength("test123")
```

### Email Validation

```go
import "github.com/bcetienne/tools-go-auth/validation"

// Create email validator
emailValidator := validation.NewEmailValidation()

// Validate email format
isValid := emailValidator.IsValidEmail("user@example.com")
fmt.Println("Email valid:", isValid) // true
```

### Access Token Management

```go
import (
    "github.com/bcetienne/tools-go-auth/auth"
    "github.com/bcetienne/tools-go-auth/model"
)

// Initialize service
accessTokenService := auth.NewAccessTokenService(config)

// Create user model
user := model.NewAuthUser(123, "uuid-here", "user@example.com")

// Generate access token
token, err := accessTokenService.CreateAccessToken(user)
if err != nil {
    log.Fatal(err)
}

// Verify access token
claims, err := accessTokenService.VerifyAccessToken(token)
if err != nil {
    // Handle expired tokens specifically
    if errors.Is(err, jwt.ErrTokenExpired) {
        fmt.Println("Token expired, refresh needed")
        // claims still available for refresh logic
    } else {
        log.Fatal(err)
    }
}
fmt.Printf("User ID: %d\n", claims.UserID)
```

### Refresh Token Management

```go
import (
    "context"
    "github.com/bcetienne/tools-go-auth/auth"
)

ctx := context.Background()

// Initialize service with database connection
refreshTokenService, err := auth.NewRefreshTokenService(ctx, db, config)
if err != nil {
    log.Fatal(err)
}

// Create refresh token
refreshToken, err := refreshTokenService.CreateRefreshToken(ctx, 123) // user ID
if err != nil {
    log.Fatal(err)
}

// Verify refresh token
isValid, err := refreshTokenService.VerifyRefreshToken(ctx, refreshToken.Token)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token valid:", *isValid)

// Revoke specific refresh token
err = refreshTokenService.RevokeRefreshToken(ctx, refreshToken.Token, 123)
if err != nil {
    log.Fatal(err)
}

// Revoke all user's refresh tokens
err = refreshTokenService.RevokeAllUserRefreshTokens(ctx, 123)
if err != nil {
    log.Fatal(err)
}

// Clean up expired tokens
err = refreshTokenService.DeleteExpiredRefreshTokens(ctx)
if err != nil {
    log.Fatal(err)
}
```

### Random String Generation

```go
import "github.com/bcetienne/tools-go-auth/lib"

// Generate secure random token
token, err := lib.GenerateRandomString(32)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token:", token) // e.g., "A7xK9mP2nQ5rT8uW1vY4zB6cD0eF3gH5"
```

## API Reference

### Configuration (`lib` package)

#### `Config` struct
```go
type Config struct {
    Issuer             string // JWT issuer
    JWTSecret          string // Secret for signing JWTs
    JWTExpiry          string // Access token expiry duration
    RefreshTokenExpiry string // Refresh token expiry duration
}
```

#### `NewConfig(issuer, JWTSecret, JWTExpiry, RefreshTokenExpiry string) *Config`
Creates a new configuration instance with the provided parameters.

### Password Hashing (`lib` package)

#### `NewPasswordHash() *PasswordHash`
Creates a new password hasher with bcrypt cost factor 14.

#### `Hash(password string) (string, error)`
Generates a secure hash of the password. Returns error for empty passwords.

#### `CheckHash(password, hash string) bool`
Verifies if password matches the hash. Returns false for empty inputs or invalid hashes.

### Password Validation (`validation` package)

#### `NewPasswordValidation() *PasswordValidation`
Creates a new password validator with default settings (min length: 8).

#### `IsPasswordStrengthEnough(password string) bool`
Validates if password meets all strength requirements.

#### `PasswordContainsUppercase(password string) bool`
Checks if password contains uppercase letters.

#### `PasswordContainsLowercase(password string) bool`
Checks if password contains lowercase letters.

#### `PasswordContainsDigit(password string) bool`
Checks if password contains numeric digits.

#### `PasswordContainsSpecialChar(password string) bool`
Checks if password contains special characters: `!@#$%^&*()-+={}[]|\:;"'<>,.?/~_`

#### `PasswordHasMinLength(password string) bool`
Checks if password meets minimum length requirement.

#### `PasswordContainsUnauthorizedWord(password string) bool`
Checks if password exactly matches any blacklisted word.

#### `SetMinLength(length int)`
Sets minimum required password length (cannot go below 8 for security).

#### `SetUnauthorizedWords(words []string)`
Sets list of forbidden words in passwords.

### Email Validation (`validation` package)

#### `NewEmailValidation() *EmailValidation`
Creates a new email validator.

#### `IsValidEmail(email string) bool`
Validates email format against RFC standards using regex: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

### Access Token Service (`auth` package)

#### `NewAccessTokenService(config *lib.Config) *AccessTokenService`
Creates a new access token service.

#### `CreateAccessToken(user *model.AuthUser) (string, error)`
Generates a JWT access token for the given user with UUID as JTI.

#### `VerifyAccessToken(token string) (*model.Claim, error)`
Verifies and parses an access token. Returns claims even for expired tokens (with jwt.ErrTokenExpired error) to enable refresh logic.

### Refresh Token Service (`auth` package)

#### `NewRefreshTokenService(ctx context.Context, db *sql.DB, config *lib.Config) (*RefreshTokenService, error)`
Creates a new refresh token service with database support. Automatically creates the `go_auth` schema and `refresh_token` table if they don't exist. Includes proper indexes for performance.

#### `CreateRefreshToken(ctx context.Context, userID int) (*model.RefreshToken, error)`
Generates a new refresh token for the user and stores it in the database. Returns the complete RefreshToken model with ID.

#### `VerifyRefreshToken(ctx context.Context, token string) (*bool, error)`
Verifies if a refresh token exists, is not revoked, and has not expired.

#### `RevokeRefreshToken(ctx context.Context, token string, userID int) error`
Revokes a specific refresh token for a user by setting revoked_at timestamp.

#### `RevokeAllUserRefreshTokens(ctx context.Context, userID int) error`
Revokes all active refresh tokens for a specific user.

#### `DeleteExpiredRefreshTokens(ctx context.Context) error`
Removes expired and revoked refresh tokens from the database.

#### `FlushRefreshTokens(ctx context.Context) error`
Removes all refresh tokens from the database (for testing/maintenance).

#### `FlushUserRefreshTokens(ctx context.Context, userID int) error`
Removes all refresh tokens for a specific user (for testing/maintenance).

### Random String Generation (`lib` package)

#### `GenerateRandomString(length int) (string, error)`
Generates a cryptographically secure random string of specified length using characters: `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-`

## Models

### AuthUser (`model` package)
```go
type AuthUser struct {
    UserID   int    `json:"user_id"`
    UserUUID string `json:"user_uuid"`
    Email    string `json:"email"`
}
```

#### `NewAuthUser(userID int, uuid, email string) *AuthUser`
Creates a new AuthUser instance.

#### Methods
- `GetUserID() int`
- `GetUserUUID() string`
- `GetEmail() string`

### RefreshToken (`model` package)
```go
type RefreshToken struct {
    RefreshTokenID int       `json:"refresh_token_id"`
    UserID         int       `json:"user_id"`
    Token          string    `json:"token"`
    ExpiresAt      time.Time `json:"expires_at"`
    CreatedAt      time.Time `json:"created_at,omitempty"`
    RevokedAt      time.Time `json:"revoked_at,omitempty"`
}
```

#### `NewRefreshToken(userID int, token string, expiresAt time.Time) *RefreshToken`
Creates a new RefreshToken instance.

### Claim (`model` package)
```go
type Claim struct {
    KeyType string `json:"key_type"` // "access" or "refresh"
    UserID  int    `json:"user_id"`
    jwt.RegisteredClaims
}
```

## Database Schema

The refresh token service automatically creates this PostgreSQL schema:

```sql
-- Schema: go_auth (created automatically)
CREATE SCHEMA go_auth;

-- Table: refresh_token (created automatically)
CREATE TABLE go_auth.refresh_token (
    refresh_token_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    UNIQUE(token)
);

-- Indexes for performance
CREATE INDEX idx_refresh_token_user_id ON go_auth.refresh_token(user_id);
CREATE INDEX idx_refresh_token_token ON go_auth.refresh_token(token);
CREATE INDEX idx_refresh_token_expires_at ON go_auth.refresh_token(expires_at);
```

## Testing

The package includes comprehensive tests with PostgreSQL test containers.

**Requirements:**
- Docker must be installed and running on your system
- Go 1.24.4 or later

```bash
# Run all tests
go test ./...

# Run specific test package
go test ./tests/auth
go test ./tests/validation
go test ./tests/lib

# Run with verbose output
go test -v ./...
```

The tests automatically start a PostgreSQL container using _testcontainers-go_, so no manual database setup is required.

## Dependencies

### Direct Dependencies
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/google/uuid` - UUID generation for JTI claims
- `github.com/lib/pq` - PostgreSQL driver
- `golang.org/x/crypto` - Bcrypt password hashing

### Test Dependencies
- `github.com/stretchr/testify` - Testing assertions
- `github.com/testcontainers/testcontainers-go` - Docker test containers
- `github.com/testcontainers/testcontainers-go/modules/postgres` - PostgreSQL test container

## Security Considerations

- **JWT Secrets**: Use strong, unique secrets for JWT signing (minimum 256 bits recommended)
- **Token Expiry**: Set appropriate expiry times (15min for access, 7d for refresh tokens recommended)
- **Password Hashing**: Uses bcrypt with cost factor 14 for secure password storage
- **Random Generation**: All random strings use `crypto/rand` for cryptographic security
- **Database Security**: Refresh tokens are stored securely with proper indexing and transaction handling
- **Password Requirements**: Enforces minimum 8 character length and cannot be lowered for security
- **Token Validation**: Includes proper error handling for expired tokens while maintaining security

## Error Handling

The package provides detailed error handling:

- **Password Validation**: Individual validation methods for granular feedback
- **JWT Tokens**: Specific handling for expired tokens vs invalid tokens
- **Database Operations**: Transaction-based operations with proper rollback
- **Input Validation**: Comprehensive validation for all inputs including token length limits

## Context Support

All refresh token operations support Go's context package for:
- Request cancellation
- Timeouts
- Request tracing
- Graceful shutdowns

## License

This project is part of the BcStudio1 tools collection.

## Development

This project is primarily hosted on GitLab (private). The GitHub repository serves as a public mirror.

For development and contributions, please use the GitLab repository when possible.
