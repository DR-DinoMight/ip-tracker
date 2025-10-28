package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/resend/resend-go/v2"
	_ "github.com/tursodatabase/libsql-client-go/libsql" // Turso driver
)

// IPEntry remains the same.
type IPEntry struct {
	IP        string
	StartTime time.Time
	EndTime   *time.Time // Pointer for nullable EndTime
}

func (e IPEntry) Duration() string {
	end := time.Now().UTC()
	if e.EndTime != nil {
		end = *e.EndTime
	}
	d := end.Sub(e.StartTime).Round(time.Second)
	return d.String()
}

// Config updated for Turso.
type Config struct {
	Username        string
	Password        string
	ResendAPIKey    string
	NotifyEmailTo   string
	NotifyEmailFrom string
	Port            string
	TursoDBURL      string // e.g., "libsql://your-db-name.turso.io"
	TursoAuthToken  string // The auth token for your database
}

// Database struct to hold the connection pool.
type Database struct {
	*sql.DB
}

var (
	config Config
	db     *Database
	// Mutex is no longer needed for history slice, as DB handles concurrency.
)

// setupDatabase connects to Turso and ensures the schema is correct.
func setupDatabase() (*Database, error) {
	if config.TursoDBURL == "" || config.TursoAuthToken == "" {
		return nil, fmt.Errorf("TURSO_DB_URL and TURSO_AUTH_TOKEN must be set")
	}

	fullURL := fmt.Sprintf("%s?authToken=%s", config.TursoDBURL, config.TursoAuthToken)

	conn, err := sql.Open("libsql", fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Create table if it doesn't exist
	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS ip_history (
			ip TEXT NOT NULL,
			start_time TEXT NOT NULL PRIMARY KEY,
			end_time TEXT
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &Database{conn}, nil
}

// getPublicIP fetches the public IP address from an external service
func getPublicIP() (string, error) {
	// Try multiple IP services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://checkip.amazonaws.com",
		"https://ifconfig.me/ip",
	}

	for _, service := range services {
		resp, err := http.Get(service)
		if err != nil {
			log.Printf("Failed to get IP from %s: %v", service, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read response from %s: %v", service, err)
				continue
			}

			ip := strings.TrimSpace(string(body))
			// Basic IP validation
			if len(ip) > 0 && len(ip) < 16 && strings.Contains(ip, ".") {
				log.Printf("Successfully got public IP from %s: %s", service, ip)
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("failed to get public IP from any service")
}

// loadHistory now queries the database.
func loadHistory() ([]IPEntry, error) {
	rows, err := db.Query("SELECT ip, start_time, end_time FROM ip_history ORDER BY start_time DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []IPEntry
	for rows.Next() {
		var entry IPEntry
		var startTimeStr string
		var endTime sql.NullString // Use sql.NullString for nullable columns
		if err := rows.Scan(&entry.IP, &startTimeStr, &endTime); err != nil {
			return nil, err
		}

		// Parse start time
		parsedStartTime, err := time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return nil, err
		}
		entry.StartTime = parsedStartTime

		// Parse end time if it exists
		if endTime.Valid {
			parsedEndTime, err := time.Parse(time.RFC3339, endTime.String)
			if err != nil {
				return nil, err
			}
			entry.EndTime = &parsedEndTime
		}
		history = append(history, entry)
	}
	return history, nil
}

// updateLatestEntry finds the current IP and sets its end_time.
func updateLatestEntry(endTime time.Time) error {
	// Find the entry with no end_time and update it.
	_, err := db.Exec(
		"UPDATE ip_history SET end_time = ? WHERE end_time IS NULL",
		endTime.Format(time.RFC3339),
	)
	return err
}

// insertNewEntry adds the new IP address to the database.
func insertNewEntry(ip string, startTime time.Time) error {
	_, err := db.Exec(
		"INSERT INTO ip_history (ip, start_time, end_time) VALUES (?, ?, NULL)",
		ip,
		startTime.Format(time.RFC3339),
	)
	return err
}

// ipTrackerHandler updated to use database functions and public IP detection.
// Returns just IP for command-line tools (curl/wget) or full HTML for browsers.
// Basic auth is only required for browser requests.
func ipTrackerHandler(w http.ResponseWriter, r *http.Request) {
	currentIP, err := getPublicIP()
	if err != nil {
		http.Error(w, "Could not determine public IP", http.StatusInternalServerError)
		log.Printf("Failed to get public IP: %v", err)
		return
	}

	// Check if request is from a browser or command-line tool
	userAgent := r.Header.Get("User-Agent")
	isBrowser := isBrowserRequest(userAgent)

	// For command-line tools (curl, wget, etc.), return just the IP (no auth required)
	if !isBrowser {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, currentIP)
		return
	}

	// For browsers, require basic authentication
	user, pass, ok := r.BasicAuth()
	if !ok || user != config.Username || pass != config.Password {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// For browsers, continue with full functionality
	history, err := loadHistory()
	if err != nil {
		http.Error(w, "Failed to load IP history", http.StatusInternalServerError)
		log.Printf("DB load error: %v", err)
		return
	}

	latestIP := ""
	if len(history) > 0 {
		latestIP = history[0].IP
	}

	if latestIP != currentIP {
		log.Printf("IP change detected: from %q to %q", latestIP, currentIP)
		now := time.Now().UTC()
		oldIP := "None"

		if len(history) > 0 {
			oldIP = history[0].IP
			if err := updateLatestEntry(now); err != nil {
				log.Printf("DB update error: %v", err)
			}
		}

		if err := insertNewEntry(currentIP, now); err != nil {
			log.Printf("DB insert error: %v", err)
		}

		// Asynchronously send notification and reload history for the view
		go sendNotification(currentIP, oldIP)
		history, _ = loadHistory() // Reload history to show the new entry
	}

	pageData := struct {
		CurrentIP string
		History   []IPEntry
	}{
		CurrentIP: currentIP,
		History:   history,
	}

	err = tmpl.Execute(w, pageData)
	if err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func main() {
	// Load configuration from environment variables
	config = Config{
		Username:        getEnv("APP_USERNAME", "admin"),
		Password:        getEnv("APP_PASSWORD", "changeme"),
		Port:            getEnv("APP_PORT", "8080"),
		ResendAPIKey:    getEnv("RESEND_API_KEY", ""),
		NotifyEmailTo:   getEnv("NOTIFY_EMAIL_TO", ""),
		NotifyEmailFrom: getEnv("NOTIFY_EMAIL_FROM", "IP Tracker <noreply@resend.dev>"),
		TursoDBURL:      getEnv("TURSO_DB_URL", ""),
		TursoAuthToken:  getEnv("TURSO_AUTH_TOKEN", ""),
	}

	var err error
	db, err = setupDatabase()
	if err != nil {
		log.Fatalf("Failed to set up database: %v", err)
	}
	defer db.Close()

	http.HandleFunc("/", ipTrackerHandler)
	log.Printf("Starting server on port %s...", config.Port)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// --- Helper functions (getEnv, sendNotification, basicAuth) and the HTML template (tmpl) remain unchanged ---
// (For brevity, they are omitted here but should be kept in your main.go file)

// isBrowserRequest detects if the request is from a browser or command-line tool
func isBrowserRequest(userAgent string) bool {
	if userAgent == "" {
		return false // No user agent = likely command-line tool
	}

	// Convert to lowercase for case-insensitive matching
	ua := strings.ToLower(userAgent)

	// Check for common command-line tools
	commandLineTools := []string{
		"curl", "wget", "httpie", "postman", "insomnia",
		"python-requests", "go-http-client", "java-http-client",
		"node-fetch", "axios", "fetch", "okhttp",
	}

	for _, tool := range commandLineTools {
		if strings.Contains(ua, tool) {
			return false
		}
	}

	// Check for browser indicators
	browserIndicators := []string{
		"mozilla", "chrome", "safari", "firefox", "edge", "opera",
		"webkit", "gecko", "trident", "msie",
	}

	for _, indicator := range browserIndicators {
		if strings.Contains(ua, indicator) {
			return true
		}
	}

	// Default to false for unknown user agents
	return false
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func sendNotification(newIP, oldIP string) {
	if config.ResendAPIKey == "" || config.NotifyEmailTo == "" {
		log.Println("Resend not configured, skipping notification.")
		return
	}

	// Validate email format
	if config.NotifyEmailFrom == "" {
		log.Println("NOTIFY_EMAIL_FROM not set, skipping notification.")
		return
	}

	client := resend.NewClient(config.ResendAPIKey)
	subject := fmt.Sprintf("Public IP Address Changed to %s", newIP)
	htmlBody := fmt.Sprintf("Your public IP address has changed.<br><br>New IP: <strong>%s</strong><br>Old IP: <strong>%s</strong>", newIP, oldIP)
	params := &resend.SendEmailRequest{From: config.NotifyEmailFrom, To: []string{config.NotifyEmailTo}, Subject: subject, Html: htmlBody}
	_, err := client.Emails.Send(params)
	if err != nil {
		log.Printf("Failed to send notification: %v", err)
		log.Printf("From: %s, To: %s", config.NotifyEmailFrom, config.NotifyEmailTo)
	} else {
		log.Printf("Sent notification for IP change to %s", newIP)
	}
}

func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != config.Username || pass != config.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

var tmpl = template.Must(template.New("webpage").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Public IP Tracker</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; color: #1c1e21; margin: 0; padding: 2rem; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { border-bottom: 2px solid #eee; padding-bottom: 0.5rem; margin-top: 0; }
        .current-ip { background-color: #e7f3ff; border: 1px solid #cce0ff; padding: 1rem; border-radius: 6px; margin-bottom: 2rem; }
        .current-ip strong { font-size: 1.5rem; color: #0056b3; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        tr:hover { background-color: #f8f9fa; }
        .status-current { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <h1>Public IP Tracker</h1>
    <div class="current-ip">
        Current Public IP: <strong>{{ .CurrentIP }}</strong>
    </div>
    <h2>IP Address History</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Start Time (UTC)</th>
                <th>End Time (UTC)</th>
                <th>Duration</th>
            </tr>
        </thead>
        <tbody>
            {{if not .History}}
                <tr><td colspan="4">No history recorded yet. An entry will be created now.</td></tr>
            {{else}}
                {{range .History}}
                    <tr>
                        <td>{{ .IP }}</td>
                        <td>{{ .StartTime.Format "2006-01-02 15:04:05" }}</td>
                        <td>
                            {{if .EndTime}}
                                {{ .EndTime.Format "2006-01-02 15:04:05" }}
                            {{else}}
                                <span class="status-current">Current</span>
                            {{end}}
                        </td>
                        <td>{{ .Duration }}</td>
                    </tr>
                {{end}}
            {{end}}
        </tbody>
    </table>
</div>
</body>
</html>
`))
