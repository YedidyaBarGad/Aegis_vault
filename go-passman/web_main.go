// go:build web
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

	"github.com/YedidyaBarGad/go-passman/models"
	"github.com/YedidyaBarGad/go-passman/storage"
	"github.com/YedidyaBarGad/go-passman/util"
	"github.com/gorilla/mux"
)

const vaultPath = "vault.json"

var (
	creds     []models.Credential
	vaultPW   []byte
	templates *template.Template
)

type PageData struct {
	Credentials []models.Credential
	Credential  *models.Credential
	Error       string
	Message     string
}

// init initializes the templates and sets up the vault path.
// It parses the HTML templates from the templates directory.
func init() {
	templates = template.Must(template.ParseFiles(
		filepath.Join("templates", "init.html"),
		filepath.Join("templates", "login.html"),
		filepath.Join("templates", "dashboard.html"),
		filepath.Join("templates", "add.html"),
		filepath.Join("templates", "update.html"),
		filepath.Join("templates", "confirm_delete.html"),
	))
	log.Println("Templates loaded.")
}

// loadVault loads the vault from the specified path using the provided password.
// It returns an error if the vault cannot be loaded.
func loadVault() error {
	var err error
	creds, err = storage.LoadVault(vaultPath, vaultPW)
	return err
}

// saveVault saves the current credentials to the vault file.
// It returns an error if the save operation fails.
func saveVault() error {
	return storage.SaveVault(vaultPath, creds, vaultPW)
}

// renderTemplate renders the specified template with the provided data.
// It handles errors by logging them and returning an HTTP error response.
func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmplName+".html", data)
	if err != nil {
		log.Printf("Template execution error for %s: %v\n", tmplName, err)
		http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// isAuthenticated is a middleware that checks if the user is authenticated.
func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(vaultPW) == 0 && r.URL.Path != "/login" && r.URL.Path != "/init" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if len(vaultPW) > 0 && len(creds) == 0 {
			if err := loadVault(); err != nil {
				log.Printf("Failed to load vault in middleware for path %s: %v", r.URL.Path, err)
				vaultPW = nil
				http.Redirect(w, r, "/login?error="+url.QueryEscape("Vault load error. Please re-login."), http.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// initHandler initializes the vault if it doesn't exist.
// It prompts the user for a master password and creates an empty vault.
func initHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(vaultPath); err == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		pw := r.FormValue("password")
		if pw == "" {
			generatedPw := util.GeneratePassword(16)
			pw = generatedPw
			log.Printf("Vault initialized with generated password: %s\n", generatedPw)
		}

		vaultPW = []byte(pw)
		creds = []models.Credential{}
		if err := saveVault(); err != nil {
			renderTemplate(w, "init", PageData{Error: "Vault initialization failed: " + err.Error()})
			return
		}
		http.Redirect(w, r, "/login?message="+url.QueryEscape("Vault initialized. Please log in."), http.StatusSeeOther)
		return
	}
	renderTemplate(w, "init", nil)
}

// loginHandler handles the login process.
// It prompts the user for the master password and loads the vault.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		vaultPW = []byte(r.FormValue("password"))
		if err := loadVault(); err != nil {
			log.Printf("Login failed: %v", err)
			renderTemplate(w, "login", PageData{Error: "Invalid password or corrupted vault."})
			return
		}
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

// dashboardHandler renders the dashboard with the list of credentials.
// It also handles any error or message passed via URL query parameters.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{Credentials: creds}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}
	if msg := r.URL.Query().Get("message"); msg != "" {
		data.Message = msg
	}
	renderTemplate(w, "dashboard", data)
}

// addHandler handles the addition of new credentials.
// It expects a POST request with the site, username, and password in the form data.
func addHandler(w http.ResponseWriter, r *http.Request) {
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

		// Removed the password strength check here.
		// Now, if password is empty, it generates one. If it's not empty, it uses what's provided.
		if password == "" {
			password = util.GeneratePassword(16)
			log.Printf("Generated password for %s: %s", site, password)
		}
		// No 'else' block for strength check anymore

		newCred := models.Credential{
			Site:     site,
			Username: username,
			Password: password, // This will be the user's input or the generated password
		}

		creds = append(creds, newCred)

		if err := saveVault(); err != nil {
			log.Printf("Error saving vault after add: %v", err)
			renderTemplate(w, "add", PageData{Credential: &newCred, Error: "Failed to save vault."})
			return
		}

		// Success! Now redirect to dashboard.
		http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' added successfully!", site)), http.StatusSeeOther)
		return // Ensure return after redirect
	}

	// For GET requests, render the empty add form
	renderTemplate(w, "add", nil)
}

// confirmDeleteHandler renders a confirmation page for deleting a credential.
// It expects the site to delete as a URL parameter.
func confirmDeleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	siteToConfirm := vars["site"]
	if siteToConfirm == "" {
		http.Error(w, "Site parameter is missing for deletion confirmation.", http.StatusBadRequest)
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

// deleteHandler handles the deletion of credentials.
// It expects a POST request with the site to delete in the form data.
func deleteHandler(w http.ResponseWriter, r *http.Request) {
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
	creds, deleted = models.DeleteCredential(creds, siteToDelete)
	if !deleted {
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape(fmt.Sprintf("Credential for '%s' not found or already deleted.", siteToDelete)), http.StatusSeeOther)
		return
	}

	if err := saveVault(); err != nil {
		log.Printf("Error saving vault after deletion: %v", err)
		http.Redirect(w, r, "/dashboard?error="+url.QueryEscape("Failed to save vault after deletion."), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' deleted successfully.", siteToDelete)), http.StatusSeeOther)
}

// updateHandler handles the update of existing credentials.
// It allows the user to change the site, username, and password of an existing credential.
// It also checks for conflicts with existing credentials.
func updateHandler(w http.ResponseWriter, r *http.Request) {
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

		passwordToSave := creds[foundIndex].Password
		if newPassword == "" {
			// If no new password is provided, generate a new one
			newPassword = util.GeneratePassword(16)
			// add popup message to inform the user in the UI

		}
		passwordToSave = newPassword

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
			creds[foundIndex].Site = newSite
			creds[foundIndex].Username = newUsername
			creds[foundIndex].Password = passwordToSave
		}

		if err := saveVault(); err != nil {
			renderTemplate(w, "update", PageData{Credential: &creds[foundIndex], Error: "Failed to save vault after update."})
			return
		}
		http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(fmt.Sprintf("Credential for '%s' updated successfully!", newSite)), http.StatusSeeOther)
		return
	}

	// GET request for update form
	cred := models.FindCredential(creds, oldSite)
	if cred == nil {
		http.Error(w, "Credential not found", http.StatusNotFound)
		return
	}
	renderTemplate(w, "update", PageData{Credential: cred})
}

// apiList returns the list of credentials in JSON format.
// This is used for API access.
func apiList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(creds); err != nil {
		http.Error(w, "Failed to encode credentials", http.StatusInternalServerError)
	}
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			http.Redirect(w, r, "/init", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	router.HandleFunc("/init", initHandler)
	router.HandleFunc("/login", loginHandler)

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
