package main

import (
	"fmt"
	"net/http"
	"strings"
)

// 1. Hardcoded Secret Key (CWE-798)
const AdminToken = "mutagen_super_secret_go_key_2026_xyz"

func handleSecureAdminConfig(w http.ResponseWriter, r *http.Request) {
	// LOGICAL BYPASS (CWE-287 / CWE-306)
	// Conceptually similar to CVE-2026-8198:
	// If the Authorization header is completely omitted, instead of returning 401 Unauthorized,
	// the function skips validation and proceeds under the assumption that it's a guest request.
	// However, it then mistakenly performs admin level actions if the query parameter "action" is "reset"!
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// If header is present, it validates it
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != AdminToken {
			http.Error(w, "Unauthorized: Invalid Admin Token", http.StatusUnauthorized)
			return
		}
	}
	// If authHeader is empty, it skips token checks (no error raised!)

	action := r.URL.Query().Get("action")
	if action == "reset" {
		// Critical admin action allowed because check was skipped!
		fmt.Fprintf(w, "SUCCESS: Database configuration reset triggered.")
		return
	}

	fmt.Fprintf(w, "Guest Action executed.")
}

func main() {
	http.HandleFunc("/admin/config", handleSecureAdminConfig)
	http.ListenAndServe(":8080", nil)
}
