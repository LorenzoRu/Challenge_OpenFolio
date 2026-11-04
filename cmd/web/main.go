package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"Challenge_OpenFolio/internal/auth"
	"Challenge_OpenFolio/internal/database"
)

const (
	sessionCookieName = "session_token"
	sessionDuration   = 24 * time.Hour
)

type server struct {
	db        *sql.DB
	templates *template.Template
}

func main() {
	db, err := database.Connect()
	if err != nil {
		log.Fatalf("Erreur connexion BDD: %v", err)
	}
	defer database.Close(db)
	if err := database.EnsureSchema(db); err != nil {
		log.Fatalf("Erreur creation schema BDD: %v", err)
	}
	if err := database.SeedDemoData(db); err != nil {
		log.Printf("Erreur initialisation donnees de demonstration: %v", err)
	}

	tmpl := template.Must(template.ParseFiles(
		"templates/construction.html",
		"templates/login.html",
		"templates/signup.html",
		"templates/admin.html",
		"templates/editor.html",
		"templates/public.html",
	))

	s := &server{db: db, templates: tmpl}

	mux := http.NewServeMux()
	// Page publique du site (en construction).
	mux.HandleFunc("GET /{$}", s.handleConstruction)
	mux.HandleFunc("GET /auth/login", s.handleLoginPage)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	// La creation de compte (signup) est protegee par le middleware d'auth.
	mux.Handle("GET /auth/signup", s.requireAuthOrSignupFirst(http.HandlerFunc(s.handleSignupPage)))
	mux.Handle("POST /auth/signup", s.requireAuthOrSignupFirst(http.HandlerFunc(s.handleSignup)))
	mux.Handle("GET /admin", s.requireAuth(http.HandlerFunc(s.handleAdmin)))
	mux.Handle("POST /admin/pages", s.requireAuth(http.HandlerFunc(s.handleCreatePage)))
	mux.Handle("GET /admin/pages/{id}/edit", s.requireAuth(http.HandlerFunc(s.handleEditPage)))
	mux.Handle("POST /admin/pages/{id}/update", s.requireAuth(http.HandlerFunc(s.handleUpdatePage)))
	mux.Handle("POST /admin/pages/{id}/delete", s.requireAuth(http.HandlerFunc(s.handleDeletePage)))

	// Route publique d'aperçu d'une page publiée.
	mux.HandleFunc("GET /u/{slug}", s.handlePublicPage)

	// Serves static assets (design tokens, styles, fonts) from the /static/ path.
	mux.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))

	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Erreur serveur: %v", err)
	}
}

// render render un template avec les donnees.
func (s *server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	tmpl := s.templates.Lookup(name)
	if tmpl == nil {
		http.Error(w, "Template introuvable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Erreur execution template %s: %v", name, err)
	}
}

// handleConstruction affiche la page publique "site en construction".
func (s *server) handleConstruction(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "construction.html", nil)
}

// renderLogin rend la page de login avec un eventuel message d'erreur.
func (s *server) renderLogin(w http.ResponseWriter, r *http.Request, email string, errMsg string) {
	s.render(w, r, "login.html", map[string]any{"Email": email, "Error": errMsg})
}

// handleLoginPage affiche le formulaire de connexion.
func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, "", "")
}

// handleLogin traite le formulaire de connexion et demarre la session.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	if email == "" || password == "" {
		s.renderLogin(w, r, email, "Email et mot de passe requis.")
		return
	}

	userID, err := database.VerifyUser(s.db, email, password)
	if err != nil {
		if errors.Is(err, database.ErrInvalidCredentials) {
			s.renderLogin(w, r, email, "Identifiants invalides.")
			return
		}
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

	token := auth.GenerateToken()
	if err := database.CreateSession(s.db, token, userID); err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleSignupPage affiche le formulaire de creation de compte admin.
func (s *server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "signup.html", nil)
}

// handleSignup traite la creation du compte admin et demarre la session.
func (s *server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/auth/signup", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	if email == "" || password == "" {
		s.render(w, r, "signup.html", map[string]any{"Error": "Email et mot de passe requis."})
		return
	}

	// Une seule creation de compte admin est autorisee.
	count, err := database.CountUsers(s.db)
	if err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		s.render(w, r, "signup.html", map[string]any{"Error": "Un seul compte admin est autorise."})
		return
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

	adminID, err := database.CreateAdmin(s.db, email, passwordHash)
	if err != nil {
		s.render(w, r, "signup.html", map[string]any{"Error": "Cet email est déjà utilise."})
		return
	}
	// Prépare des pages de démonstration pour le nouvel admin.
	if err := database.SeedPagesForUser(s.db, adminID); err != nil {
		log.Printf("Erreur initialisation pages de demonstration: %v", err)
	}

	token := auth.GenerateToken()
	if err := database.CreateSession(s.db, token, adminID); err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleLogout supprime la session et deconnecte l'utilisateur.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if token := r.Header.Get("Cookie"); token != "" {
			if value, ok := extractCookie(token, sessionCookieName); ok {
				database.DeleteSession(s.db, value)
			}
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// handleAdmin affiche le dashboard admin protege avec les donnees reelles.
func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	stats, err := database.GetStats(s.db)
	if err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	pages, err := database.ListPages(s.db, userID)
	if err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	previewSlug, err := database.GetPreviewSlug(s.db, userID)
	if err != nil {
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

	s.render(w, r, "admin.html", map[string]any{
		"Email":       email,
		"Stats":       stats,
		"Pages":       pages,
		"PreviewSlug": previewSlug,
		"Error":       dashboardError(r.URL.Query().Get("error")),
		"Success":     dashboardSuccess(r.URL.Query().Get("success")),
	})
}

// handleCreatePage cree une nouvelle page de portfolio.
func (s *server) handleCreatePage(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	r.ParseForm()

	title := strings.TrimSpace(r.FormValue("title"))
	slug := strings.TrimSpace(r.FormValue("slug"))
	status := normalizeStatus(r.FormValue("status"))
	if slug == "" {
		slug = slugify(title)
	}
	if title == "" || slug == "" {
		http.Redirect(w, r, "/admin?error=invalid", http.StatusSeeOther)
		return
	}

	if _, err := database.CreatePage(s.db, userID, title, slug, status); err != nil {
		if errors.Is(err, database.ErrSlugTaken) {
			http.Redirect(w, r, "/admin?error=slug", http.StatusSeeOther)
			return
		}
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?success=created", http.StatusSeeOther)
}

// handleEditPage affiche l'editeur placeholder d'une page.
func (s *server) handleEditPage(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	pageID := parsePageID(r.PathValue("id"))
	if pageID == 0 {
		http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
		return
	}
	page, err := database.GetPage(s.db, userID, pageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
			return
		}
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

	s.render(w, r, "editor.html", map[string]any{"Email": email, "Page": page})
}

// handleUpdatePage met a jour le titre, le slug et le statut d'une page.
func (s *server) handleUpdatePage(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	pageID := parsePageID(r.PathValue("id"))
	if pageID == 0 {
		http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
		return
	}
	r.ParseForm()

	title := strings.TrimSpace(r.FormValue("title"))
	slug := strings.TrimSpace(r.FormValue("slug"))
	status := normalizeStatus(r.FormValue("status"))
	if slug == "" {
		slug = slugify(title)
	}
	if title == "" || slug == "" {
		http.Redirect(w, r, "/admin?error=invalid", http.StatusSeeOther)
		return
	}

	if err := database.UpdatePage(s.db, userID, pageID, title, slug, status); err != nil {
		switch {
		case errors.Is(err, database.ErrSlugTaken):
			http.Redirect(w, r, "/admin?error=slug", http.StatusSeeOther)
		case errors.Is(err, sql.ErrNoRows):
			http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
		default:
			http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/admin?success=updated", http.StatusSeeOther)
}

// handleDeletePage supprime une page de portfolio.
func (s *server) handleDeletePage(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	pageID := parsePageID(r.PathValue("id"))
	if pageID == 0 {
		http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
		return
	}

	if err := database.DeletePage(s.db, userID, pageID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Redirect(w, r, "/admin?error=notfound", http.StatusSeeOther)
			return
		}
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?success=deleted", http.StatusSeeOther)
}

// contentBlock represente un bloc de contenu stocke en JSON dans une page.
type contentBlock struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Text  string `json:"text"`
	URL   string `json:"url"`
}

// handlePublicPage rend publiquement une page publiee via son slug.
func (s *server) handlePublicPage(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	page, err := database.GetPublishedPageBySlug(s.db, slug)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

	var blocks []contentBlock
	if len(page.Content) > 0 {
		if err := json.Unmarshal(page.Content, &blocks); err != nil {
			log.Printf("Contenu JSON invalide pour la page %s: %v", page.Slug, err)
			blocks = nil
		}
	}

	s.render(w, r, "public.html", map[string]any{"Page": page, "Blocks": blocks})
}

// dashboardError traduit un code d'erreur de l'URL en message lisible.
func dashboardError(code string) string {
	switch code {
	case "invalid":
		return "Le titre et le slug sont obligatoires."
	case "slug":
		return "Ce slug est déjà utilisé."
	case "notfound":
		return "Page introuvable."
	default:
		return ""
	}
}

// dashboardSuccess traduit un code de succes de l'URL en message lisible.
func dashboardSuccess(code string) string {
	switch code {
	case "created":
		return "Page créée avec succès."
	case "updated":
		return "Page mise à jour."
	case "deleted":
		return "Page supprimée."
	default:
		return ""
	}
}

// normalizeStatus limite les statuts de page aux valeurs autorisees.
func normalizeStatus(raw string) string {
	if raw == "published" {
		return "published"
	}
	return "draft"
}

// parsePageID convertit l'identifiant de page present dans l'URL.
func parsePageID(raw string) int64 {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

var slugReplacer = strings.NewReplacer(
	"à", "a", "â", "a", "ä", "a", "á", "a", "ã", "a",
	"ç", "c",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"î", "i", "ï", "i", "í", "i",
	"ô", "o", "ö", "o", "ó", "o", "õ", "o",
	"ù", "u", "û", "u", "ü", "u", "ú", "u",
	"ÿ", "y", "ñ", "n",
	"œ", "oe", "æ", "ae",
)

// slugify transforme un titre en slug URL compatible.
func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = slugReplacer.Replace(value)

	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case r == ' ' || r == '-' || r == '_' || r == '.' || r == '\'' || r == '/':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// requireAuth protege les routes privees (ex: /admin).
func (s *server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := s.currentUser(r); !ok {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthOrSignupFirst protege les routes privees (ex: /admin), sauf pour
// /auth/signup lorsqu'aucun compte n'existe encore (premiere creation admin).
func (s *server) requireAuthOrSignupFirst(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/signup" {
			if count, err := database.CountUsers(s.db); err == nil && count == 0 {
				next.ServeHTTP(w, r)
				return
			}
		}
		s.requireAuth(next).ServeHTTP(w, r)
	})
}

// currentUser retourne l'utilisateur connecte via le cookie de session.
func (s *server) currentUser(r *http.Request) (int64, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return 0, "", false
	}
	userID, email, err := database.GetSessionUser(s.db, cookie.Value)
	if err != nil {
		return 0, "", false
	}
	return userID, email, true
}

// extractCookie recupere la valeur d'un cookie depuis un en-tete "Cookie".
func extractCookie(header string, name string) (string, bool) {
	parts := strings.Split(header, ";")
	for _, part := range parts {
		if kv := strings.SplitN(strings.TrimSpace(part), "=", 2); len(kv) == 2 {
			if kv[0] == name {
				return kv[1], true
			}
		}
	}
	return "", false
}
