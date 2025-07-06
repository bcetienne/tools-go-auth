# Go Auth Package

A comprehensive authentication utility package for Go applications, providing secure password validation, email validation, and cryptographic utilities.

## Features

### 🔐 Password Security
- **Secure Hashing**: Bcrypt with cost factor 14
- **Comprehensive Validation**: Uppercase, lowercase, digits, special characters
- **Configurable Requirements**: Minimum length, blacklisted words
- **Built-in Protection**: Prevents weak passwords and common attack vectors

### 📧 Email Validation
- **RFC-Compliant**: Standard email format validation
- **Performance Optimized**: Pre-compiled regex patterns
- **Simple API**: Single function validation

### 🎲 Cryptographic Utilities
- **Secure Random Strings**: Uses `crypto/rand` for token generation
- **Alphanumeric + Hyphen**: Safe character set for URLs and tokens
- **Error Handling**: Proper error propagation for crypto failures

## Installation

```bash
go get gitlab.com/bcstudio1/tools/go-auth
```

## Quick Start

### Password Hashing

```go
import "gitlab.com/bcstudio1/tools/go-auth/lib"

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
import "gitlab.com/bcstudio1/tools/go-auth/validation"

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
import "gitlab.com/bcstudio1/tools/go-auth/validation"

// Create email validator
emailValidator := validation.NewEmailValidation()

// Validate email format
isValid := emailValidator.IsValidEmail("user@example.com")
fmt.Println("Email valid:", isValid) // true
```

### Random String Generation

```go
import "gitlab.com/bcstudio1/tools/go-auth/lib"

// Generate secure random token
token, err := lib.GenerateRandomString(32)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token:", token) // e.g., "A7xK9mP2nQ5rT8uW1vY4zB6cD0eF3gH5"
```

## API Reference

### Password Hashing (`lib` package)

#### `NewPasswordHash() PasswordHash`
Creates a new password hasher with bcrypt cost factor 14.

#### `Hash(password string) (string, error)`
Generates a secure hash of the password. Returns error for empty passwords.

#### `CheckHash(password, hash string) bool`
Verifies if password matches the hash. Returns false for empty inputs or invalid hashes.

### Password Validation (`validation` package)

#### `NewPasswordValidation() PasswordValidation`
Creates validator with secure defaults (8 char minimum, comprehensive rules).

#### Configuration Methods
- `SetMinLength(minLength int)` - Set minimum length (min: 8 chars)
- `SetUnauthorizedWords(words []string)` - Set password blacklist

#### Validation Methods
- `IsPasswordStrengthEnough(password string) bool` - Complete validation
- `PasswordContainsLowercase(password string) bool` - Check lowercase letters
- `PasswordContainsUppercase(password string) bool` - Check uppercase letters
- `PasswordContainsDigit(password string) bool` - Check numeric digits
- `PasswordContainsSpecialChar(password string) bool` - Check special characters
- `PasswordHasMinLength(password string) bool` - Check minimum length
- `PasswordContainsUnauthorizedWord(password string) bool` - Check blacklist

### Email Validation (`validation` package)

#### `NewEmailValidation() EmailValidation`
Creates email validator with RFC-compliant regex.

#### `IsValidEmail(email string) bool`
Validates email format. Returns true for valid emails.

### Random Utilities (`lib` package)

#### `GenerateRandomString(n int) (string, error)`
Generates cryptographically secure random string of length n.

Character set: `0-9A-Za-z-`

## Security Features

- **High-Cost Bcrypt**: Cost factor 14 provides strong protection against brute-force attacks
- **Crypto-Secure Random**: Uses `crypto/rand` for token generation
- **Input Validation**: Prevents empty passwords and invalid inputs
- **Configurable Security**: Adjustable requirements while maintaining baseline security
- **Salt Generation**: Automatic salt generation ensures unique hashes

## Best Practices

### Password Security
```go
// ✅ Good: Strong validation
validator := validation.NewPasswordValidation()
validator.SetMinLength(12)
validator.SetUnauthorizedWords([]string{"password", "admin"})

// ✅ Good: Always check errors
hash, err := hasher.Hash(password)
if err != nil {
    return fmt.Errorf("hashing failed: %w", err)
}
```

### Token Generation
```go
// ✅ Good: Sufficient length for security
sessionToken, err := lib.GenerateRandomString(32)
refreshToken, err := lib.GenerateRandomString(64)

// ✅ Good: Always handle crypto errors
if err != nil {
    return fmt.Errorf("token generation failed: %w", err)
}
```

## Testing

The package includes comprehensive test coverage for all components:

```bash
go test ./...
```

## Requirements

- Go 1.21+
- Dependencies: `golang.org/x/crypto/bcrypt`

## License

Private package - internal use only.

## Contributing

This is a private utility package. For issues or feature requests, contact the development team.