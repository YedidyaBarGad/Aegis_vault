//go:build web
// +build web

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YedidyaBarGad/go-passman/auth"
	"github.com/YedidyaBarGad/go-passman/models"
	"github.com/YedidyaBarGad/go-passman/storage"
	"github.com/YedidyaBarGad/go-passman/util"
	"github.com/gorilla/mux"
)

// usersDir is the directory where individual user vaults and the users.json file will be stored
const usersDir = "users_data"
const userVaultPrefix = "vault_"
const userVaultSuffix = ".json"
const allUsersPath = "users_data/users.json"

var (
	templates *template.Template
	allUsers  *models.Users // Global variable to hold all registered users
)

// Session represents a user's active session
type Session struct {
	Username  string
	VaultPW   []byte              // Master password for the current session (decrypted vault key)
	UserCreds []models.Credential // Loaded credentials for the current user
	VaultPath string              // Path to the current user's vault file
}

// PageData is the data structure used to pass data to templates
type PageData struct {
	Error       string
	Message     string
	Credentials []models.Credential // List of credentials for the dashboard
	Credential  *models.Credential  // For add/update forms
}

// In-memory map to store active sessions (for simplicity; use a proper session store in production)
var activeSessions = make(map[string]*Session) // map[sessionID]Session

func init() {

	templates = template.Must(template.ParseFiles(
		filepath.Join("templates", "init.html"), // Still here, but less used
		filepath.Join("templates", "login.html"),
		filepath.Join("templates", "register.html"),
		filepath.Join("templates", "dashboard.html"),
		filepath.Join("templates", "add.html"),
		filepath.Join("templates", "update.html"),
		filepath.Join("templates", "confirm_delete.html"),
	))
	log.Println("Templates loaded.")

	// Create users data directory if it doesn't exist
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		log.Fatalf("Failed to create users data directory: %v", err)
	}

	// Load all users from users.json on startup
	var err error
	loadedUsers, err := models.LoadUsers(allUsersPath) // Assign to local var first
	if err != nil {
		log.Printf("Error loading users from %s: %v", allUsersPath, err)
	}
	allUsers = loadedUsers // Then assign address to global pointer
}

// getUserSession retrieves the current user's session from the request context (or by cookie)
func getUserSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil // No session cookie
	}
	sessionID := cookie.Value
	return activeSessions[sessionID]
}

// createSession creates a new session for a user
func createSession(username string, vaultPW []byte, userVaultPath string) (*Session, string) {
	sessionID := util.GeneratePassword(32) // Generate a cryptographically random session ID
	session := &Session{
		Username:  username,
		VaultPW:   vaultPW,
		VaultPath: userVaultPath,
	}
	activeSessions[sessionID] = session
	return session, sessionID
}

// removeSession removes a session
func removeSession(sessionID string) {
	delete(activeSessions, sessionID)
}

// renderTemplate renders the specified template with the provided data.
func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmplName+".html", data)
	if err != nil {
		http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// isAuthenticated is a middleware that checks if the user is authenticated.
func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := getUserSession(r)
		if session == nil {
			// Invalidate the cookie if it exists but points to no session
			cookie, err := r.Cookie("session_id")
			if err == nil {
				removeSession(cookie.Value)
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   false, // Set to true in production
					SameSite: http.SameSiteLaxMode,
				})
			}
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Please log in to access this page."), http.StatusSeeOther)
			return
		}

		// If credentials are not loaded for this session, try to load them
		if session.UserCreds == nil {
			loadedCreds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
			if err != nil {
				log.Printf("Failed to load vault for user %s in middleware for path %s: %v", session.Username, r.URL.Path, err)
				// Critical error: vault couldn't be loaded, likely wrong password or corrupted. Force re-login.
				cookie, _ := r.Cookie("session_id") // We know it exists
				removeSession(cookie.Value)
				http.SetCookie(w, &http.Cookie{ // Expire the invalid cookie
					Name:     "session_id",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   false, // Set to true in production
					SameSite: http.SameSiteLaxMode,
				})
				http.Redirect(w, r, "/login?error="+url.QueryEscape("Vault load error. Please re-login. Your vault might be corrupted or password changed."), http.StatusSeeOther)
				return
			}
			session.UserCreds = loadedCreds
		}
		next.ServeHTTP(w, r)
	})
}

// rootHandler redirects based on whether any users are registered
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if allUsers.Number == 0 { // Check the Number field of the Users struct
		http.Redirect(w, r, "/register", http.StatusSeeOther) // New users register first
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// registerHandler handles new user registration.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if username == "" || password == "" || confirmPassword == "" {
			renderTemplate(w, "register", PageData{Error: "All fields are required."})
			return
		}

		if password != confirmPassword {
			renderTemplate(w, "register", PageData{Error: "Passwords do not match."})
			return
		}

		// Enforce password strength
		if !util.PasswordStrength(password) {
			renderTemplate(w, "register", PageData{Error: "Password must be at least 8 characters long and include uppercase, lowercase, a digit, and a special character."})
			return
		}

		if user, err := models.FindUser(username, allUsers); user != nil || err != nil { // Call method on global allUsers
			renderTemplate(w, "register", PageData{Error: "Username already exists."})
			return
		}

		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			log.Printf("Error hashing password during registration: %v", err)
			renderTemplate(w, "register", PageData{Error: "Error processing password."})
			return
		}

		userVaultFileName := fmt.Sprintf("%s%s%s", userVaultPrefix, username, userVaultSuffix)
		userVaultPath := filepath.Join(usersDir, userVaultFileName)

		// Create an empty vault file for the new user, encrypted with their master password
		if err := storage.SaveVault(userVaultPath, []models.Credential{}, []byte(password)); err != nil {
			log.Printf("Error initializing vault for new user %s: %v", username, err)
			renderTemplate(w, "register", PageData{Error: "Failed to initialize user vault. Please try again."})
			return
		}

		// Add the new user to the allUsers list and save it
		if err := models.AddUser(username, hashedPassword, userVaultFileName, allUsersPath, allUsers); err != nil {
			log.Printf("Error saving new user %s: %v", username, err)
			renderTemplate(w, "register", PageData{Error: "Failed to save user data."})
			return
		}
		log.Printf("New user '%s' registered and vault initialized at '%s.", username, allUsersPath)
		http.Redirect(w, r, "/login?message="+url.QueryEscape("Registration successful. Please log in."), http.StatusSeeOther)
		return
	}
	renderTemplate(w, "register", nil)
}

// loginHandler handles the login process.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := models.FindUser(username, allUsers) // Use the method on the allUsers pointer
		log.Printf("Login attempt for user: %s", username)
		if user == nil || !auth.AuthenticateUser(username, password, allUsers) {
			log.Printf("Login failed for user %s: %v", username, err)
			renderTemplate(w, "login", PageData{Error: "Invalid username or password."})
			return
		}

		userVaultPath := filepath.Join(usersDir, user.VaultFileName)
		// Attempt to load and decrypt the user's vault to verify master password and load creds
		_, errLoad := storage.LoadVault(userVaultPath, []byte(password))
		if errLoad != nil {
			log.Printf("Failed to load/decrypt vault for user %s during login: %v", username, errLoad)
			renderTemplate(w, "login", PageData{Error: "Invalid password or corrupted vault. Please try again."})
			return
		}

		// Create and set session
		_, sessionID := createSession(username, []byte(password), userVaultPath)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(24 * time.Hour), // Session expires in 24 hours
		})

		log.Printf("User %s logged in successfully.", username)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	data := PageData{}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}
	if msg := r.URL.Query().Get("message"); msg != "" {
		data.Message = msg
	}
	renderTemplate(w, "login", data)
}

// logoutHandler clears the session and redirects to login.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		removeSession(cookie.Value)
	}

	// Expire the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Immediately expire
		HttpOnly: true,
		// Secure:   true, // Set to true in production
		Secure:   false, // For local development (HTTP)
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("User logged out.")
	http.Redirect(w, r, "/login?message="+url.QueryEscape("Logged out successfully."), http.StatusSeeOther)
}

// dashboardHandler renders the dashboard with the list of credentials for the current user.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	data := PageData{Credentials: session.UserCreds}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}
	if msg := r.URL.Query().Get("message"); msg != "" {
		data.Message = msg
	}
	renderTemplate(w, "dashboard", data)
}

// addHandler handles the addition of new credentials for the current user.
func addHandler(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	if r.Method == http.MethodPost {
		r.ParseForm()
		site := r.FormValue("site")
		username := r.FormValue("username")
		password := r.FormValue("password")

		if site == "" || username == "" {
			data := PageData{
				Credential: &models.Credential{Site: site, Username: username},
				Error:      "Site and Username are required.",
			}
			renderTemplate(w, "add", data)
			return
		}

		for _, existingCred := range session.UserCreds {
			if strings.EqualFold(existingCred.Site, site) {
				data := PageData{
					Credential: &models.Credential{Site: site, Username: username},
					Error:      fmt.Sprintf("A credential for site '%s' already exists.", site),
				}
				renderTemplate(w, "add", data)
				return
			}
		}

		if password == "" {
			password = util.GeneratePassword(16) // Use util.GeneratePassword for actual password generation
		}

		newCred := models.Credential{
			Site:     site,
			Username: username,
			Password: password, // Store as plaintext for now, encryption happens at saveVault
		}

		session.UserCreds = append(session.UserCreds, newCred)

		if err := storage.SaveVault(session.VaultPath, session.UserCreds, session.VaultPW); err != nil {
			log.Printf("Error saving vault after add for user %s: %v", session.Username, err)
			renderTemplate(w, "add", PageData{Credential: &newCred, Error: "Failed to save vault."})
			return
		}

		http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' added successfully!", site)), http.StatusSeeOther)
		return
	}
	renderTemplate(w, "add", nil)
}

// confirmDeleteHandler renders a confirmation page for deleting a credential.
func confirmDeleteHandler(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	vars := mux.Vars(r)
	siteToConfirm := vars["site"]
	if siteToConfirm == "" {
		http.Error(w, "Site parameter is missing for deletion confirmation.", http.StatusBadRequest)
		return
	}

	cred := models.FindCredential(session.UserCreds, siteToConfirm)
	if cred == nil {
		http.Error(w, "Credential not found for confirmation.", http.StatusNotFound)
		return
	}

	data := PageData{Credential: cred}
	renderTemplate(w, "confirm_delete", data)
}

// deleteHandler handles the deletion of credentials for the current user.
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	siteToDelete := r.FormValue("site")
	if siteToDelete == "" {
		http.Error(w, "Site parameter is missing in form for deletion.", http.StatusBadRequest)
		return
	}

	var deleted bool
	session.UserCreds, deleted = models.DeleteCredential(session.UserCreds, siteToDelete)
	if !deleted {
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape(fmt.Sprintf("Credential for '%s' not found or already deleted.", siteToDelete)), http.StatusSeeOther)
		return
	}

	if err := storage.SaveVault(session.VaultPath, session.UserCreds, session.VaultPW); err != nil {
		log.Printf("Error saving vault after deletion for user %s: %v", session.Username, err)
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape("Failed to save vault after deletion."), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' deleted successfully.", siteToDelete)), http.StatusSeeOther)
}

// updateHandler handles the update of existing credentials for the current user.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	vars := mux.Vars(r)
	oldSite := vars["site"]

	if r.Method == http.MethodPost {
		r.ParseForm()
		siteToFind := r.FormValue("original_site")
		if siteToFind == "" {
			siteToFind = oldSite
		}

		newSite := r.FormValue("site")
		newUsername := r.FormValue("username")
		newPassword := r.FormValue("password")

		if newSite == "" || newUsername == "" {
			credToDisplay := models.FindCredential(session.UserCreds, siteToFind)
			renderTemplate(w, "update", PageData{Credential: credToDisplay, Error: "Site and Username cannot be empty."})
			return
		}

		foundIndex := -1
		for i, cred := range session.UserCreds {
			if strings.EqualFold(cred.Site, siteToFind) {
				foundIndex = i
				break
			}
		}

		if foundIndex == -1 {
			http.Error(w, "Credential to update not found.", http.StatusNotFound)
			return
		}

		passwordToSave := session.UserCreds[foundIndex].Password // Keep existing password if not provided
		if newPassword != "" {
			passwordToSave = newPassword
		}

		if strings.EqualFold(newSite, siteToFind) {
			session.UserCreds[foundIndex].Username = newUsername
			session.UserCreds[foundIndex].Password = passwordToSave
		} else {
			// Check for conflicts with other credentials *for the current user*
			for i, cred := range session.UserCreds {
				if i != foundIndex && strings.EqualFold(cred.Site, newSite) {
					credToDisplay := models.FindCredential(session.UserCreds, siteToFind)
					renderTemplate(w, "update", PageData{Credential: credToDisplay, Error: fmt.Sprintf("New site name '%s' conflicts with another existing credential.", newSite)})
					return
				}
			}
			session.UserCreds[foundIndex].Site = newSite
			session.UserCreds[foundIndex].Username = newUsername
			session.UserCreds[foundIndex].Password = passwordToSave
		}

		if err := storage.SaveVault(session.VaultPath, session.UserCreds, session.VaultPW); err != nil {
			log.Printf("Error saving vault after update for user %s: %v", session.Username, err)
			renderTemplate(w, "update", PageData{Credential: &session.UserCreds[foundIndex], Error: "Failed to save vault after update."})
			return
		}
		http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' updated successfully!", newSite)), http.StatusSeeOther)
		return
	}

	// GET request for update form
	cred := models.FindCredential(session.UserCreds, oldSite)
	if cred == nil {
		http.Error(w, "Credential not found", http.StatusNotFound)
		return
	}
	renderTemplate(w, "update", PageData{Credential: cred})
}

// apiList returns the list of credentials for the current user in JSON format.
func apiList(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(session.UserCreds); err != nil {
		http.Error(w, "Failed to encode credentials", http.StatusInternalServerError)
	}
}

func main() {
	models.InitKey()
	router := mux.NewRouter()

	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/logout", logoutHandler).Methods("POST") // Add logout route

	authenticatedRouter := router.PathPrefix("/").Subrouter()
	authenticatedRouter.Use(isAuthenticated)

	authenticatedRouter.HandleFunc("/dashboard", dashboardHandler)
	authenticatedRouter.HandleFunc("/add", addHandler)
	authenticatedRouter.HandleFunc("/update/{site}", updateHandler)
	authenticatedRouter.HandleFunc("/confirm-delete/{site}", confirmDeleteHandler)
	authenticatedRouter.HandleFunc("/delete", deleteHandler).Methods("POST")

	authenticatedRouter.HandleFunc("/api/creds", apiList).Methods("GET")

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
