package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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

// ErrSlugTaken est retourné lorsqu'un slug de page est déjà utilisé.
var ErrSlugTaken = errors.New("slug déjà utilisé")

// Page représente une page du portfolio.
type Page struct {
	ID        int64
	UserID    int64
	Title     string
	Slug      string
	Status    string
	Content   []byte
	UpdatedAt time.Time
}

// Stats regroupe les indicateurs affichés sur le dashboard.
type Stats struct {
	ActiveProjects int64
	Templates      int64
	Media          int64
}

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

// EnsureSchema crée les tables nécessaires (auth + dashboard).
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
		`CREATE TABLE IF NOT EXISTS pages (
			id SERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			title TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
			content JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS projects (
			id SERIAL PRIMARY KEY,
			title TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS templates (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS media (
			id SERIAL PRIMARY KEY,
			filename TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'image',
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS app_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
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

// CountUsers retourne le nombre d'utilisateurs en base.
func CountUsers(db *sql.DB) (int64, error) {
	var count int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("echec comptage utilisateurs: %w", err)
	}
	return count, nil
}

// GetMaintenance indique si le mode maintenance est actif.
func GetMaintenance(db *sql.DB) (bool, error) {
	var value string
	err := db.QueryRow(`SELECT value FROM app_meta WHERE key = 'maintenance'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("échec lecture mode maintenance: %w", err)
	}
	return value == "on", nil
}

// SetMaintenance active ou désactive le mode maintenance.
func SetMaintenance(db *sql.DB, enabled bool) error {
	value := "off"
	if enabled {
		value = "on"
	}
	_, err := db.Exec(
		`INSERT INTO app_meta (key, value) VALUES ('maintenance', $1)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		value,
	)
	if err != nil {
		return fmt.Errorf("échec mise à jour mode maintenance: %w", err)
	}
	return nil
}

// GetStats retourne les indicateurs clés du dashboard.
func GetStats(db *sql.DB) (Stats, error) {
	var stats Stats
	if err := db.QueryRow(`SELECT COUNT(*) FROM projects WHERE status = 'active'`).Scan(&stats.ActiveProjects); err != nil {
		return stats, fmt.Errorf("échec comptage projets: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM templates`).Scan(&stats.Templates); err != nil {
		return stats, fmt.Errorf("échec comptage templates: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM media`).Scan(&stats.Media); err != nil {
		return stats, fmt.Errorf("échec comptage médias: %w", err)
	}
	return stats, nil
}

// ListPages retourne les pages d'un utilisateur, les plus récentes en premier.
func ListPages(db *sql.DB, userID int64) ([]Page, error) {
	rows, err := db.Query(
		`SELECT id, user_id, title, slug, status, content, updated_at
		 FROM pages WHERE user_id = $1 ORDER BY updated_at DESC, id DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("échec liste pages: %w", err)
	}
	defer rows.Close()

	var pages []Page
	for rows.Next() {
		var p Page
		if err := rows.Scan(&p.ID, &p.UserID, &p.Title, &p.Slug, &p.Status, &p.Content, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("échec lecture page: %w", err)
		}
		pages = append(pages, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("échec parcours pages: %w", err)
	}
	return pages, nil
}

// CreatePage crée une page de portfolio et retourne son id.
func CreatePage(db *sql.DB, userID int64, title, slug, status string) (int64, error) {
	var id int64
	err := db.QueryRow(
		`INSERT INTO pages (user_id, title, slug, status) VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, title, slug, status,
	).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrSlugTaken
		}
		return 0, fmt.Errorf("échec création page: %w", err)
	}
	return id, nil
}

// UpdatePage met à jour le titre, le slug et le statut d'une page.
func UpdatePage(db *sql.DB, userID, pageID int64, title, slug, status string) error {
	result, err := db.Exec(
		`UPDATE pages SET title = $1, slug = $2, status = $3, updated_at = NOW()
		 WHERE id = $4 AND user_id = $5`,
		title, slug, status, pageID, userID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSlugTaken
		}
		return fmt.Errorf("échec mise à jour page: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeletePage supprime une page appartenant à l'utilisateur.
func DeletePage(db *sql.DB, userID, pageID int64) error {
	result, err := db.Exec(`DELETE FROM pages WHERE id = $1 AND user_id = $2`, pageID, userID)
	if err != nil {
		return fmt.Errorf("échec suppression page: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetPage retourne une page d'un utilisateur par son id.
func GetPage(db *sql.DB, userID, pageID int64) (Page, error) {
	var p Page
	err := db.QueryRow(
		`SELECT id, user_id, title, slug, status, content, updated_at
		 FROM pages WHERE id = $1 AND user_id = $2`,
		pageID, userID,
	).Scan(&p.ID, &p.UserID, &p.Title, &p.Slug, &p.Status, &p.Content, &p.UpdatedAt)
	if err != nil {
		return Page{}, err
	}
	return p, nil
}

// GetPublishedPageBySlug retourne une page publiée via son slug (route publique).
func GetPublishedPageBySlug(db *sql.DB, slug string) (Page, error) {
	var p Page
	err := db.QueryRow(
		`SELECT id, user_id, title, slug, status, content, updated_at
		 FROM pages WHERE slug = $1 AND status = 'published'`,
		slug,
	).Scan(&p.ID, &p.UserID, &p.Title, &p.Slug, &p.Status, &p.Content, &p.UpdatedAt)
	if err != nil {
		return Page{}, err
	}
	return p, nil
}

// GetPreviewSlug retourne le slug de la page d'accueil si définie, sinon la première page publiée.
func GetPreviewSlug(db *sql.DB, userID int64) (string, error) {
	home, err := GetHomePage(db)
	if err == nil {
		return home.Slug, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	var slug string
	err = db.QueryRow(
		`SELECT slug FROM pages WHERE user_id = $1 AND status = 'published' ORDER BY id ASC LIMIT 1`,
		userID,
	).Scan(&slug)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("échec recherche page aperçu: %w", err)
	}
	return slug, nil
}

const homePageMetaKey = "home_page_id"

// GetHomePageID retourne l'id de la page définie comme accueil (0 si aucune).
func GetHomePageID(db *sql.DB) (int64, error) {
	var value string
	err := db.QueryRow(`SELECT value FROM app_meta WHERE key = $1`, homePageMetaKey).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("échec lecture page d'accueil: %w", err)
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, nil
	}
	return id, nil
}

// SetHomePage définit la page servie sur la route "/".
func SetHomePage(db *sql.DB, pageID int64) error {
	_, err := db.Exec(
		`INSERT INTO app_meta (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		homePageMetaKey, strconv.FormatInt(pageID, 10),
	)
	if err != nil {
		return fmt.Errorf("échec enregistrement page d'accueil: %w", err)
	}
	return nil
}

// ClearHomePage retire la page d'accueil (retour à la page de construction).
func ClearHomePage(db *sql.DB) error {
	_, err := db.Exec(`DELETE FROM app_meta WHERE key = $1`, homePageMetaKey)
	if err != nil {
		return fmt.Errorf("échec suppression page d'accueil: %w", err)
	}
	return nil
}

// GetHomePage retourne la page d'accueil si elle existe et est publiée.
func GetHomePage(db *sql.DB) (Page, error) {
	id, err := GetHomePageID(db)
	if err != nil {
		return Page{}, err
	}
	if id == 0 {
		return Page{}, sql.ErrNoRows
	}

	var p Page
	err = db.QueryRow(
		`SELECT id, user_id, title, slug, status, content, updated_at
		 FROM pages WHERE id = $1 AND status = 'published'`,
		id,
	).Scan(&p.ID, &p.UserID, &p.Title, &p.Slug, &p.Status, &p.Content, &p.UpdatedAt)
	if err != nil {
		return Page{}, err
	}
	return p, nil
}

// SeedDemoData prépare les données de démonstration du dashboard.
func SeedDemoData(db *sql.DB) error {
	if err := seedStats(db); err != nil {
		return err
	}

	rows, err := db.Query(`SELECT id FROM users`)
	if err != nil {
		return fmt.Errorf("échec liste utilisateurs pour seed: %w", err)
	}
	defer rows.Close()

	var userIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("échec lecture utilisateur pour seed: %w", err)
		}
		userIDs = append(userIDs, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("échec parcours utilisateurs pour seed: %w", err)
	}

	for _, id := range userIDs {
		if err := SeedPagesForUser(db, id); err != nil {
			return err
		}
	}
	return nil
}

// SeedPagesForUser crée les pages de démonstration d'un utilisateur (une seule fois).
func SeedPagesForUser(db *sql.DB, userID int64) error {
	key := fmt.Sprintf("pages_seeded_%d", userID)
	var value string
	err := db.QueryRow(`SELECT value FROM app_meta WHERE key = $1`, key).Scan(&value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("échec lecture état seed pages: %w", err)
	}

	pages := []struct {
		title   string
		slug    string
		status  string
		content string
	}{
		{
			title:   "Accueil",
			slug:    "accueil",
			status:  "published",
			content: `[{"type":"heading","text":"Bienvenue sur mon portfolio"},{"type":"text","text":"Je conçois des expériences web simples, élégantes et centrées sur l'essentiel."}]`,
		},
		{
			title:   "À propos",
			slug:    "a-propos",
			status:  "draft",
			content: `[{"type":"heading","text":"À propos"},{"type":"text","text":"Quelques mots sur mon parcours et ma façon de travailler."}]`,
		},
		{
			title:   "Projets",
			slug:    "projets",
			status:  "published",
			content: `[{"type":"heading","text":"Mes projets"},{"type":"text","text":"Une sélection de réalisations récentes."}]`,
		},
		{
			title:   "Contact",
			slug:    "contact",
			status:  "draft",
			content: `[{"type":"heading","text":"Contact"},{"type":"text","text":"Une idée, un projet ? Parlons-en."}]`,
		},
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("échec transaction seed pages: %w", err)
	}
	defer tx.Rollback()

	for _, p := range pages {
		if _, err := tx.Exec(
			`INSERT INTO pages (user_id, title, slug, status, content)
			 VALUES ($1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (slug) DO NOTHING`,
			userID, p.title, p.slug, p.status, p.content,
		); err != nil {
			return fmt.Errorf("échec insertion page démo: %w", err)
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO app_meta (key, value) VALUES ($1, 'true') ON CONFLICT (key) DO NOTHING`,
		key,
	); err != nil {
		return fmt.Errorf("échec marquage seed pages: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("échec validation seed pages: %w", err)
	}
	return nil
}

// seedStats insère les projets, templates et médias de démonstration (une seule fois).
func seedStats(db *sql.DB) error {
	var value string
	err := db.QueryRow(`SELECT value FROM app_meta WHERE key = 'demo_stats_seeded'`).Scan(&value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("échec lecture état seed stats: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("échec transaction seed stats: %w", err)
	}
	defer tx.Rollback()

	projects := []string{"Portfolio personnel", "Site vitrine", "Application mobile"}
	for _, title := range projects {
		if _, err := tx.Exec(`INSERT INTO projects (title, status) VALUES ($1, 'active')`, title); err != nil {
			return fmt.Errorf("échec insertion projet démo: %w", err)
		}
	}

	templates := []string{"Minimal", "Grid", "Editorial", "Dark", "Creative"}
	for _, name := range templates {
		if _, err := tx.Exec(`INSERT INTO templates (name) VALUES ($1)`, name); err != nil {
			return fmt.Errorf("échec insertion template démo: %w", err)
		}
	}

	for i := 1; i <= 12; i++ {
		if _, err := tx.Exec(`INSERT INTO media (filename, kind) VALUES ($1, 'image')`, fmt.Sprintf("media-%02d.jpg", i)); err != nil {
			return fmt.Errorf("échec insertion média démo: %w", err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO app_meta (key, value) VALUES ('demo_stats_seeded', 'true') ON CONFLICT (key) DO NOTHING`,
	); err != nil {
		return fmt.Errorf("échec marquage seed stats: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("échec validation seed stats: %w", err)
	}
	return nil
}

// isUniqueViolation indique si l'erreur PostgreSQL est une violation d'unicité.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
