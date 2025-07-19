# Go Auth Package

A comprehensive authentication utility package for Go applications, providing secure password validation, email validation, JWT token management, and cryptographic utilities.

## Features

### 🔐 Password Security
- **Secure Hashing**: Bcrypt with configurable cost factor (default: 14)
- **Comprehensive Validation**: Uppercase, lowercase, digits, special characters
- **Configurable Requirements**: Minimum length, blacklisted words
- **Built-in Protection**: Prevents weak passwords and common attack vectors

### 📧 Email Validation
- **RFC-Compliant**: Standard email format validation
- **Performance Optimized**: Pre-compiled regex patterns
- **Simple API**: Single function validation

### 🎫 JWT Token Management
- **Access Tokens**: Short-lived tokens for API authentication
- **Refresh Tokens**: Long-lived tokens for session management with database persistence
- **Secure Generation**: Uses HS256 signing with configurable secrets
- **Token Verification**: Built-in validation with proper error handling

### 🎲 Cryptographic Utilities
- **Secure Random Strings**: Uses `crypto/rand` for token generation
- **Alphanumeric + Hyphen**: Safe character set for URLs and tokens
- **Error Handling**: Proper error propagation for crypto failures

## Installation

```bash
go get github.com/bcetienne/tools-go-auth
```

## Configuration

Create a configuration object with your settings:

```go
config := &lib.Config{
Issuer:             "your-app.com",
JWTSecret:          "your-secure-jwt-secret",
JWTExpiry:          "15m",        // Access token expiry
RefreshTokenExpiry: "7d",         // Refresh token expiry
}
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

// Create validator with defaults
validator := validation.NewPasswordValidation()

// Customize requirements
validator.SetMinLength(12)
validator.SetUnauthorizedWords([]string{"password", "admin", "123456"})

// Validate password strength
isStrong := validator.IsPasswordStrengthEnough("MyStrongP@ssw0rd!")
fmt.Println("Password strong:", isStrong) // true

// Check individual requirements
hasUpper := validator.PasswordContainsUppercase("test")
hasDigit := validator.PasswordContainsDigit("test123")
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
user := &model.AuthUser{
UserID: 123,
Email:  "user@example.com",
}

// Generate access token
token, err := accessTokenService.CreateAccessToken(user)
if err != nil {
log.Fatal(err)
}

// Verify access token
claims, err := accessTokenService.VerifyAccessToken(token)
if err != nil {
log.Fatal(err)
}
fmt.Printf("User ID: %d\n", claims.UserID)
```

### Refresh Token Management

```go
import "github.com/bcetienne/tools-go-auth/auth"

// Initialize service with database connection
refreshTokenService, err := auth.NewRefreshTokenService(db, config)
if err != nil {
log.Fatal(err)
}

// Create refresh token
token, err := refreshTokenService.CreateRefreshToken(123) // user ID
if err != nil {
log.Fatal(err)
}

// Verify refresh token
isValid, err := refreshTokenService.VerifyRefreshToken(token)
if err != nil {
log.Fatal(err)
}

// Revoke refresh token
err = refreshTokenService.RevokeRefreshToken(token, 123)
if err != nil {
log.Fatal(err)
}

// Revoke all user's refresh tokens
err = refreshTokenService.RevokeAllUserRefreshTokens(123)
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

### Password Hashing (`lib` package)

#### `NewPasswordHash() PasswordHash`
Creates a new password hasher with bcrypt cost factor 14.

#### `Hash(password string) (string, error)`
Generates a secure hash of the password. Returns error for empty passwords.

#### `CheckHash(password, hash string) bool`
Verifies if password matches the hash. Returns false for empty inputs or invalid hashes.

### Password Validation (`validation` package)

#### `NewPasswordValidation() PasswordValidation`
Creates a new password validator with default settings.

#### `IsPasswordStrengthEnough(password string) bool`
Validates if password meets all strength requirements.

#### `PasswordContainsUppercase(password string) bool`
Checks if password contains uppercase letters.

#### `PasswordContainsLowercase(password string) bool`
Checks if password contains lowercase letters.

#### `PasswordContainsDigit(password string) bool`
Checks if password contains numeric digits.

#### `PasswordContainsSpecialChar(password string) bool`
Checks if password contains special characters.

#### `SetMinLength(length int)`
Sets minimum required password length.

#### `SetUnauthorizedWords(words []string)`
Sets list of forbidden words in passwords.

### Email Validation (`validation` package)

#### `NewEmailValidation() EmailValidation`
Creates a new email validator.

#### `IsValidEmail(email string) bool`
Validates email format against RFC standards.

### Access Token Service (`auth` package)

#### `NewAccessTokenService(config *lib.Config) AccessTokenService`
Creates a new access token service.

#### `CreateAccessToken(user *model.AuthUser) (string, error)`
Generates a JWT access token for the given user.

#### `VerifyAccessToken(token string) (*model.Claim, error)`
Verifies and parses an access token, returning claims if valid.

### Refresh Token Service (`auth` package)

#### `NewRefreshTokenService(db *sql.DB, config *lib.Config) (*RefreshTokenService, error)`
Creates a new refresh token service with database support. Automatically creates required schema and tables.

#### `CreateRefreshToken(userID int) (string, error)`
Generates a new refresh token for the user and stores it in the database.

#### `VerifyRefreshToken(token string) (*bool, error)`
Verifies if a refresh token exists and is valid in the database.

#### `RevokeRefreshToken(token string, userID int) error`
Revokes a specific refresh token for a user.

#### `RevokeAllUserRefreshTokens(userID int) error`
Revokes all refresh tokens for a specific user.

#### `FlushRefreshTokens() error`
Removes all expired refresh tokens from the database.

### Random String Generation (`lib` package)

#### `GenerateRandomString(length int) (string, error)`
Generates a cryptographically secure random string of specified length using alphanumeric characters and hyphens.

## Models

### AuthUser (`model` package)
```go
type AuthUser struct {
UserID   int    `json:"user_id"`
UserUUID string `json:"user_uuid"`
Email    string `json:"email"`
}
```

### Claim (`model` package)
```go
type Claim struct {
KeyType string `json:"key_type"` // "access" or "refresh"
UserID  int    `json:"user_id"`
jwt.RegisteredClaims
}
```

## Database Requirements

The refresh token service requires a PostgreSQL database. The service will automatically create the required schema and table:

```sql
-- Schema: auth_module (created automatically)
-- Table: refresh_tokens (created automatically)
```

## Testing

The package includes comprehensive tests with PostgreSQL test containers.

**Requirements:**
- Docker must be installed and running on your system

```bash
go test ./...
```

The tests automatically start a PostgreSQL container using _testcontainers-go_, so no manual database setup is required.

## Security Considerations

- **JWT Secrets**: Use strong, unique secrets for JWT signing
- **Token Expiry**: Set appropriate expiry times for access and refresh tokens
- **Password Hashing**: Uses bcrypt with cost factor 14 for secure password storage
- **Random Generation**: All random strings use `crypto/rand` for cryptographic security
- **Database Security**: Refresh tokens are stored securely with proper indexing

## License

This project is part of the BcStudio1 tools collection.
