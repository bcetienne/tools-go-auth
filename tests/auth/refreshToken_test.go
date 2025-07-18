package auth

import (
	"context"
	"database/sql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"gitlab.com/bcstudio1/tools/go-auth/auth"
	"log"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"gitlab.com/bcstudio1/tools/go-auth/lib"
)

var (
	db     *sql.DB
	config *lib.Config
)

// TestMain is a special function that runs before all tests in this package.
// We use it to start our database in a Docker container.
func TestMain(m *testing.M) {
	ctx := context.Background()

	database := "go_auth_module_test"
	username := "user"
	password := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(database),
		postgres.WithUsername(username),
		postgres.WithPassword(password),
		postgres.BasicWaitStrategies(),
	)

	defer func() {
		if err = testcontainers.TerminateContainer(postgresContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("failed to get connection string: %s", err)
		return
	}

	// Connect to database
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Cannot to connect to database: %s", err)
	}
	defer db.Close()

	// Check that the connection is established
	err = db.Ping()
	if err != nil {
		log.Fatalf("Cannot ping database: %s", err)
	}

	// Initialize fake config
	config = &lib.Config{
		RefreshTokenExpiry: "24h",
	}

	// Run tests
	exitCode := m.Run()

	// Exit with the tests exit code
	os.Exit(exitCode)
}

// setupService is a helper function to initialize the service and clean the database
// before each test to ensure their independence.
func setupService(t *testing.T) *auth.RefreshTokenService {
	// NewRefreshTokenService will create the schema and table on the first call.
	service, err := auth.NewRefreshTokenService(db, config)
	require.NoError(t, err)

	// We clear the table to ensure the test starts from a clean state.
	err = service.FlushRefreshTokens()
	require.NoError(t, err)

	return service
}

func TestNewRefreshTokenService(t *testing.T) {
	t.Run("Should create schema and table if not exists", func(t *testing.T) {
		_, err := auth.NewRefreshTokenService(db, config)
		require.NoError(t, err)

		// Verify that the schema and table exist
		var exists bool
		query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'go_auth' AND table_name = 'refresh_token'
		)`
		err = db.QueryRow(query).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "The table 'refresh_token' should exist in the 'go_auth' schema")
	})
}

func TestCreateRefreshToken(t *testing.T) {
	service := setupService(t)
	userID := 123

	t.Run("Should create a refresh token", func(t *testing.T) {
		refreshToken, err := service.CreateRefreshToken(userID)

		require.NoError(t, err)
		assert.NotNil(t, refreshToken)
		assert.Positive(t, refreshToken.RefreshTokenID)
		assert.Equal(t, userID, refreshToken.UserID)
		assert.NotEmpty(t, refreshToken.Token)
		// Verify that the token has a 24h lifetime
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), refreshToken.ExpiresAt, time.Second*5)
	})
}

func TestRevokeRefreshToken(t *testing.T) {
	service := setupService(t)
	userID := 456

	// Create a token to revoke
	refreshToken, err := service.CreateRefreshToken(userID)
	require.NoError(t, err)

	t.Run("should revoke an existing token", func(t *testing.T) {
		err := service.RevokeRefreshToken(refreshToken.Token, userID)
		require.NoError(t, err)

		// Verify that it is revoked by checking the revoked_at column
		var revokedAt sql.NullTime
		query := `SELECT revoked_at FROM go_auth.refresh_token WHERE token = $1`
		err = db.QueryRow(query, refreshToken.Token).Scan(&revokedAt)
		require.NoError(t, err)
		assert.True(t, revokedAt.Valid, "revoked_at should not be NULL")
	})

	t.Run("Should not fail if token does not exist", func(t *testing.T) {
		// The UPDATE query will not affect any rows, so no error will be returned.
		err = service.RevokeRefreshToken("non-existent-token", userID)
		require.NoError(t, err)
	})
}

func TestRevokeAllUserRefreshTokens(t *testing.T) {
	service := setupService(t)
	userID := 789

	// Create several tokens for the user
	_, err := service.CreateRefreshToken(userID)
	require.NoError(t, err)
	_, err = service.CreateRefreshToken(userID)
	require.NoError(t, err)

	t.Run("should revoke all tokens for a user", func(t *testing.T) {
		err := service.RevokeAllUserRefreshTokens(userID)
		require.NoError(t, err)

		// Verify that all tokens for this user are revoked
		var count int
		query := `SELECT COUNT(*) FROM go_auth.refresh_token WHERE user_id = $1 AND revoked_at IS NULL`
		err = db.QueryRow(query, userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "There should be no active tokens for this user")
	})
}

func TestFlushUserRefreshTokens(t *testing.T) {
	service := setupService(t)
	userID1 := 111
	userID2 := 222

	// Create tokens for two different users
	_, err := service.CreateRefreshToken(userID1)
	require.NoError(t, err)
	_, err = service.CreateRefreshToken(userID1)
	require.NoError(t, err)
	_, err = service.CreateRefreshToken(userID2)
	require.NoError(t, err)

	t.Run("should delete all tokens for a specific user", func(t *testing.T) {
		err := service.FlushUserRefreshTokens(userID1)
		require.NoError(t, err)

		// Verify that the tokens for userID1 have been deleted
		var count1 int
		query1 := `SELECT COUNT(*) FROM go_auth.refresh_token WHERE user_id = $1`
		err = db.QueryRow(query1, userID1).Scan(&count1)
		require.NoError(t, err)
		assert.Equal(t, 0, count1)

		// Verify that the tokens for userID2 are still present
		var count2 int
		query2 := `SELECT COUNT(*) FROM go_auth.refresh_token WHERE user_id = $1`
		err = db.QueryRow(query2, userID2).Scan(&count2)
		require.NoError(t, err)
		assert.Equal(t, 1, count2)
	})
}
