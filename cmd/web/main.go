package main

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
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

	tmpl := template.Must(template.ParseFiles(
		"templates/login.html",
		"templates/signup.html",
		"templates/admin.html",
	))

	s := &server{db: db, templates: tmpl}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.handleLoginPage)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	// La creation de compte (signup) est protegee par le middleware d'auth.
	mux.Handle("GET /auth/signup", s.requireAuth(http.HandlerFunc(s.handleSignupPage)))
	mux.Handle("POST /auth/signup", s.requireAuth(http.HandlerFunc(s.handleSignup)))
	mux.Handle("GET /admin", s.requireAuth(http.HandlerFunc(s.handleAdmin)))

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

// handleAdmin affiche le dashboard admin protege.
func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	_ = userID
	s.render(w, r, "admin.html", map[string]any{"Email": email})
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
