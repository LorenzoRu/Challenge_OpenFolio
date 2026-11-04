package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"Challenge_OpenFolio/internal/auth"
)

const (
	defaultHost     = "localhost"
	defaultPort     = "5432"
	defaultUser     = "openfolio"
	defaultPassword = "changeme"
	defaultDB       = "openfolio"
)

// getEnv retourne la valeur de l'env ou une valeur par defaut si vide.
func getEnv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// ErrInvalidCredentials est retourné lors d'un échec de connexion.
var ErrInvalidCredentials = errors.New("identifiants invalides")

// Connect ouvre la connexion à la base PostgreSQL.
func Connect() (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("POSTGRES_HOST", defaultHost),
		getEnv("POSTGRES_PORT", defaultPort),
		getEnv("POSTGRES_USER", defaultUser),
		getEnv("POSTGRES_PASSWORD", defaultPassword),
		getEnv("POSTGRES_DB", defaultDB),
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("échec ouverture base de données: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("échec ping base de données: %w", err)
	}
	return db, nil
}

func Close(db *sql.DB) error {
	return db.Close()
}

// EnsureSchema crée les tables nécessaires (users, sessions).
func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("échec création schéma: %w", err)
		}
	}
	return nil
}

// CreateAdmin crée un compte admin (hash bcrypt fourni) et retourne son id.
func CreateAdmin(db *sql.DB, email, passwordHash string) (int64, error) {
	result, err := db.Exec(
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		email, passwordHash,
	)
	if err != nil {
		return 0, fmt.Errorf("échec création admin: %w", err)
	}
	return result.LastInsertId()
}

// VerifyUser vérifie les identifiants (email + mot de passe haché) et retourne l'id utilisateur.
func VerifyUser(db *sql.DB, email, password string) (int64, error) {
	var userID int64
	var passwordHash string
	err := db.QueryRow(
		`SELECT id, password_hash FROM users WHERE email = $1`,
		email,
	).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvalidCredentials
		}
		return 0, fmt.Errorf("échec recherche utilisateur: %w", err)
	}
	if !auth.CheckPassword(password, passwordHash) {
		return 0, ErrInvalidCredentials
	}
	return userID, nil
}

// CreateSession crée une session (token) pour un utilisateur.
func CreateSession(db *sql.DB, token string, userID int64) error {
	_, err := db.Exec(
		`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token, userID, time.Now().Add(24*time.Hour),
	)
	if err != nil {
		return fmt.Errorf("échec création session: %w", err)
	}
	return nil
}

// DeleteSession supprime une session.
func DeleteSession(db *sql.DB, token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token = $1`, token)
	if err != nil {
		return fmt.Errorf("échec suppression session: %w", err)
	}
	return nil
}

// GetSessionUser retourne l'id et l'email de l'utilisateur associé à un token de session.
func GetSessionUser(db *sql.DB, token string) (int64, string, error) {
	var userID int64
	var email string
	err := db.QueryRow(
		`SELECT s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1 AND s.expires_at > NOW()`,
		token,
	).Scan(&userID, &email)
	return userID, email, err
}
