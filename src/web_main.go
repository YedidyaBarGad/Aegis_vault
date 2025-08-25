//go:build web
// +build web

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/YedidyaBarGad/go-passman/auth"
	"github.com/YedidyaBarGad/go-passman/models"
	"github.com/YedidyaBarGad/go-passman/storage"
	"github.com/YedidyaBarGad/go-passman/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/crypto/bcrypt"
)

// Aegis Vault
// usersDir is the directory where individual user vaults and the users.json file will be stored
const usersDir = "users_data"
const allUsersPath = "users_data/users.json"
const jwtCookieName = "session_token"

var (
	templates    *template.Template
	allUsers     *models.Users
	jwtSecretKey []byte // The secret key for signing JWTs
)

// AuthClaims represents the JWT claims
type AuthClaims struct {
	Username  string `json:"username"`
	VaultPath string `json:"vaultPath"`
	VaultPW   string `json:"vaultPW"`
	jwt.RegisteredClaims
}

// PageData is the data structure used to pass data to templates
type PageData struct {
	Error       string
	Message     string
	Credentials []models.Credential
	Credential  *models.Credential
}

// Session represents a user's active session.
type Session struct {
	Username  string
	VaultPW   []byte
	UserCreds []models.Credential
	VaultPath string
}

func init() {
	// Load HTML templates
	templates = template.Must(template.ParseFiles(
		filepath.Join("templates", "login.html"),
		filepath.Join("templates", "register.html"),
		filepath.Join("templates", "dashboard.html"),
		filepath.Join("templates", "add.html"),
		filepath.Join("templates", "update.html"),
		filepath.Join("templates", "confirm_delete.html"),
	))
	log.Println("Templates loaded.")

	// Ensure users data directory exists
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		log.Fatalf("Failed to create users data directory: %v", err)
	}

	// Ensure .env file exists and load environment variables
	ensureEnvFileExists()
	godotenv.Load()
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY environment variable is not set.")
	}
	fmt.Printf("Using JWT_SECRET_KEY (length: %d)...\n", len(secretKey))
	jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtSecretKey) == 0 {
		log.Fatal("JWT_SECRET_KEY environment variable is not set or is empty.")
	}

	// Load existing users or initialize empty users list
	loadedUsers, err := models.LoadUsers(allUsersPath)
	if err != nil || loadedUsers == nil {
		log.Printf("No existing users found or error loading users: %v", err)
		allUsers = &models.Users{
			Number: 0,
			Users:  []models.User{},
		}
	} else {
		allUsers = loadedUsers
		log.Printf("Loaded %d users from %s.", allUsers.Number, allUsersPath)
	}
}

// generateJWT creates a new signed JWT for the user.
func generateJWT(username string, vaultPW []byte, userVaultPath string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &AuthClaims{
		Username:  username,
		VaultPath: userVaultPath,
		VaultPW:   string(vaultPW),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// parseJWT validates and parses the JWT from the request cookie.
func parseJWT(r *http.Request) (*AuthClaims, error) {
	cookie, err := r.Cookie(jwtCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, fmt.Errorf("no session cookie found")
		}
		return nil, fmt.Errorf("error getting cookie: %w", err)
	}

	tokenString := cookie.Value
	claims := &AuthClaims{}

	// parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return claims, nil
}

// renderTemplate renders the specified template with the provided data.
func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmplName+".html", data)
	if err != nil {
		http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// isAuthenticated is a middleware that checks for a valid JWT token.
func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := parseJWT(r)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			// Invalidate the cookie and redirect to login
			http.SetCookie(w, &http.Cookie{
				Name:     jwtCookieName,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   false, // Set to true in production
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Please log in to access this page."), http.StatusSeeOther)
			return
		}

		session := &Session{
			Username:  claims.Username,
			VaultPath: claims.VaultPath,
			VaultPW:   []byte(claims.VaultPW),
		}

		loadedCreds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
		if err != nil {
			log.Printf("Failed to load vault for user %s: %v", session.Username, err)
			http.SetCookie(w, &http.Cookie{
				Name:     jwtCookieName,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Vault load error. Please re-login."), http.StatusSeeOther)
			return
		}
		session.UserCreds = loadedCreds

		// Pass the session down to the handler by making it a parameter.
		// We'll update handlers to accept the session directly.
		r.Header.Set("X-Session-User", session.Username)
		r.Header.Set("X-Session-VaultPath", session.VaultPath)
		r.Header.Set("X-Session-VaultPW", string(session.VaultPW))

		next.ServeHTTP(w, r)
	})
}

// Helper function to retrieve session from headers set by the middleware
func getSessionFromRequest(r *http.Request) *Session {
	return &Session{
		Username:  r.Header.Get("X-Session-User"),
		VaultPath: r.Header.Get("X-Session-VaultPath"),
		VaultPW:   []byte(r.Header.Get("X-Session-VaultPW")),
	}
}

// rootHandler redirects based on whether any users are registered
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if allUsers.Number == 0 {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
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

		if !util.PasswordStrength(password) {
			renderTemplate(w, "register", PageData{Error: "Password must be at least 8 characters long and include uppercase, lowercase, a digit, and a special character."})
			return
		}

		if allUsers == nil {
			allUsers = &models.Users{Number: 0, Users: []models.User{}}
		}

		if user, err := models.FindUser(username, allUsers); user != nil || err != nil {
			log.Printf("Username conflict for %s: user=%v, err=%v", username, user, err)
			renderTemplate(w, "register", PageData{Error: "Username already exists."})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password for user %s: %v", username, err)
			renderTemplate(w, "register", PageData{Error: "Failed to process password. Please try again."})
			return
		}

		userVaultFileName := storage.GetVaultPath(username, "")
		userVaultPath := filepath.Join(usersDir, userVaultFileName)

		if err := storage.SaveVault(userVaultPath, []models.Credential{}, []byte(password)); err != nil {
			log.Printf("Error initializing vault for new user %s: %v", username, err)
			renderTemplate(w, "register", PageData{Error: "Failed to initialize user vault. Please try again."})
			return
		}

		if err := models.AddUser(username, string(hashedPassword), userVaultFileName, allUsersPath, allUsers); err != nil {
			log.Printf("Error saving new user %s: %v", username, err)
			renderTemplate(w, "register", PageData{Error: "Failed to save user data."})
			return
		}
		log.Printf("New user '%s' registered and vault initialized at '%s'.", username, userVaultPath)
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

		user, err := models.FindUser(username, allUsers)
		log.Printf("Login attempt for user: %s", username)
		if user == nil {
			log.Printf("User %s not found: %v", username, err)
			renderTemplate(w, "login", PageData{Error: "Invalid username or password."})
			return
		}

		if !auth.AuthenticateUser(username, password, allUsers) {
			log.Printf("Authentication failed for user %s", username)
			renderTemplate(w, "login", PageData{Error: "Invalid username or password."})
			return
		}

		userVaultPath := filepath.Join(usersDir, user.VaultFileName)
		_, errLoad := storage.LoadVault(userVaultPath, []byte(password))
		if errLoad != nil {
			log.Printf("Failed to load/decrypt vault for user %s during login: %v", username, errLoad)
			renderTemplate(w, "login", PageData{Error: "Invalid password or corrupted vault. Please try again."})
			return
		}

		// Generate and set JWT
		tokenString, err := generateJWT(username, []byte(password), userVaultPath)
		if err != nil {
			log.Printf("Failed to generate JWT: %v", err)
			renderTemplate(w, "login", PageData{Error: "Failed to create session. Please try again."})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     jwtCookieName,
			Value:    tokenString,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(24 * time.Hour),
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
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("User logged out.")
	http.Redirect(w, r, "/login?message="+url.QueryEscape("Logged out successfully."), http.StatusSeeOther)
}

// dashboardHandler renders the dashboard with the list of credentials for the current user.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session := getSessionFromRequest(r) // Get session from headers
	creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
	if err != nil {
		log.Printf("Dashboard handler failed to load vault for user %s: %v", session.Username, err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to load vault. Please re-login."), http.StatusSeeOther)
		return
	}
	data := PageData{Credentials: creds}
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
	session := getSessionFromRequest(r)

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

		creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
		if err != nil {
			log.Printf("Add handler failed to load vault for user %s: %v", session.Username, err)
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to load vault. Please re-login."), http.StatusSeeOther)
			return
		}

		for _, existingCred := range creds {
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
			password = util.GeneratePassword(16)
		}

		newCred := models.Credential{
			Site:     site,
			Username: username,
			Password: password,
		}

		creds = append(creds, newCred)

		if err := storage.SaveVault(session.VaultPath, creds, session.VaultPW); err != nil {
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
	session := getSessionFromRequest(r)
	vars := mux.Vars(r)
	siteToConfirm := vars["site"]
	if siteToConfirm == "" {
		http.Error(w, "Site parameter is missing for deletion confirmation.", http.StatusBadRequest)
		return
	}

	creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to load vault. Please re-login."), http.StatusSeeOther)
		return
	}

	cred := models.FindCredential(creds, siteToConfirm)
	if cred == nil {
		http.Error(w, "Credential not found for confirmation.", http.StatusNotFound)
		return
	}

	data := PageData{Credential: cred}
	renderTemplate(w, "confirm_delete", data)
}

// deleteHandler handles the deletion of credentials for the current user.
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	session := getSessionFromRequest(r)
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

	creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to load vault. Please re-login."), http.StatusSeeOther)
		return
	}

	var deleted bool
	creds, deleted = models.DeleteCredential(creds, siteToDelete)
	if !deleted {
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape(fmt.Sprintf("Credential for '%s' not found or already deleted.", siteToDelete)), http.StatusSeeOther)
		return
	}

	if err := storage.SaveVault(session.VaultPath, creds, session.VaultPW); err != nil {
		log.Printf("Error saving vault after deletion for user %s: %v", session.Username, err)
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape("Failed to save vault after deletion."), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' deleted successfully.", siteToDelete)), http.StatusSeeOther)
}

// updateHandler handles the update of existing credentials for the current user.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	session := getSessionFromRequest(r)
	vars := mux.Vars(r)
	oldSite := vars["site"]

	creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Failed to load vault. Please re-login."), http.StatusSeeOther)
		return
	}

	// Handle form submission
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
			credToDisplay := models.FindCredential(creds, siteToFind)
			renderTemplate(w, "update", PageData{Credential: credToDisplay, Error: "Site and Username cannot be empty."})
			return
		}

		foundIndex := -1
		for i, cred := range creds {
			if strings.EqualFold(cred.Site, siteToFind) {
				foundIndex = i
				break
			}
		}

		if foundIndex == -1 {
			http.Error(w, "Credential to update not found.", http.StatusNotFound)
			return
		}

		// Determine the password to save
		passwordToSave := creds[foundIndex].Password
		if newPassword != "" {
			passwordToSave = newPassword
		}

		// Check for site name conflicts if the site name has changed
		if strings.EqualFold(newSite, siteToFind) {
			creds[foundIndex].Username = newUsername
			creds[foundIndex].Password = passwordToSave
		} else {
			for i, cred := range creds {
				if i != foundIndex && strings.EqualFold(cred.Site, newSite) {
					credToDisplay := models.FindCredential(creds, siteToFind)
					renderTemplate(w, "update", PageData{Credential: credToDisplay, Error: fmt.Sprintf("New site name '%s' conflicts with another existing credential.", newSite)})
					return
				}
			}
			// No conflicts, proceed with update
			creds[foundIndex].Site = newSite
			creds[foundIndex].Username = newUsername
			creds[foundIndex].Password = passwordToSave
		}

		// Save the updated credentials
		if err := storage.SaveVault(session.VaultPath, creds, session.VaultPW); err != nil {
			log.Printf("Error saving vault after update for user %s: %v", session.Username, err)
			renderTemplate(w, "update", PageData{Credential: &creds[foundIndex], Error: "Failed to save vault after update."})
			return
		}
		http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' updated successfully!", newSite)), http.StatusSeeOther)
		return
	}

	// Render the update form with existing credential data
	cred := models.FindCredential(creds, oldSite)
	if cred == nil {
		http.Error(w, "Credential not found", http.StatusNotFound)
		return
	}
	renderTemplate(w, "update", PageData{Credential: cred})
}

// apiList returns the list of credentials for the current user in JSON format.
func apiList(w http.ResponseWriter, r *http.Request) {
	session := getSessionFromRequest(r)
	creds, err := storage.LoadVault(session.VaultPath, session.VaultPW)
	if err != nil {
		http.Error(w, "Failed to load vault.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(creds); err != nil {
		http.Error(w, "Failed to encode credentials", http.StatusInternalServerError)
	}
}

// ensureEnvFile exists checks for the presence of a .env file.
// If it does not exist, it creates one and populates it with a
// cryptographically secure JWT_SECRET_KEY.
func ensureEnvFileExists() {
	// Define the name of the environment file.
	envFileName := ".env"

	// Check if the file already exists.
	if _, err := os.Stat(envFileName); os.IsNotExist(err) {
		// The file does not exist, so we will create it.
		fmt.Printf("%s not found. Generating a new one...\n", envFileName)
		jwtKey := make([]byte, 32)
		_, err := rand.Read(jwtKey)
		if err != nil {
			log.Fatalf("Failed to generate random JWT key: %v", err)
		}
		encodedJwtKey := base64.URLEncoding.EncodeToString(jwtKey)

		// Generate a separate, secure USERS_FILE_ENCRYPTION_KEY.
		// This key is for symmetric encryption of the users.json file.
		encryptionKey := make([]byte, 32)
		_, err = rand.Read(encryptionKey)
		if err != nil {
			log.Fatalf("Failed to generate random encryption key: %v", err)
		}
		encodedEncryptionKey := base64.URLEncoding.EncodeToString(encryptionKey)

		// Construct the content to be written to the file.
		content := fmt.Sprintf("JWT_SECRET_KEY=%s\nUSERS_FILE_ENCRYPTION_KEY=%s\n", encodedJwtKey, encodedEncryptionKey)

		// Write the content to the new .env file.
		err = os.WriteFile(envFileName, []byte(content), 0600) // 0600 gives read/write permissions only to the owner.
		if err != nil {
			log.Fatalf("Failed to write to %s: %v", envFileName, err)
		}

		fmt.Printf("Successfully created %s with new JWT_SECRET_KEY and USERS_FILE_ENCRYPTION_KEY.\n", envFileName)
	} else if err != nil {
		// Handle other potential errors, like permissions issues.
		log.Fatalf("Failed to check for %s: %v", envFileName, err)
	} else {
		// The file already exists.
		fmt.Printf("%s already exists. Skipping creation.\n", envFileName)
	}
}

// openbrowser tries to open the URL in a browser, depending on the OS.
func openbrowser(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("cmd", "/c", "start", "", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func main() {
	// Set up the router and routes
	router := mux.NewRouter()

	router.HandleFunc("/", rootHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/logout", logoutHandler).Methods("POST")

	authenticatedRouter := router.PathPrefix("/").Subrouter()
	authenticatedRouter.Use(isAuthenticated)

	authenticatedRouter.HandleFunc("/dashboard", dashboardHandler)
	authenticatedRouter.HandleFunc("/add", addHandler)
	authenticatedRouter.HandleFunc("/update/{site}", updateHandler)
	authenticatedRouter.HandleFunc("/confirm-delete/{site}", confirmDeleteHandler)
	authenticatedRouter.HandleFunc("/delete", deleteHandler).Methods("POST")
	authenticatedRouter.HandleFunc("/api/creds", apiList).Methods("GET")
	go func() {
		log.Println("Server running at http://localhost:8080")
		if err := http.ListenAndServe(":8080", router); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait a moment for the server to be ready
	time.Sleep(1 * time.Second)

	// Automatically open the web browser to the correct URL
	log.Println("Attempting to open browser...")
	if err := open.Start("http://localhost:8080"); err != nil {
		log.Printf("Failed to open browser: %v", err)
	}

	// Use a blocking call to keep the main function from exiting
	// since the server is now running in a separate goroutine.
	select {}
}
