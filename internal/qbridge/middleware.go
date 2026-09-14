// Code moved from the original main.go monolith during the internal/ restructure.
// See README "Project Structure". Part of the Qwen bridge core (package qbridge).

package qbridge

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"
)

func toJSON(v interface{}) string {
    b, _ := json.Marshal(v)
    return string(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(v)
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Include-All-Features, x-api-key, anthropic-version")
        if r.Method == "OPTIONS" {
            w.WriteHeader(200)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func checkAuth(r *http.Request) bool {
    if !config.Auth.Enabled {
        return true
    }
    authHeader := r.Header.Get("Authorization")
    provided := authHeader
    if len(authHeader) >= 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
        provided = authHeader[7:]
    }
    // Anthropic clients send the API key via x-api-key header
    if provided == "" {
        provided = r.Header.Get("x-api-key")
    }
    return provided == config.Auth.Token
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !config.Auth.Enabled {
            next(w, r)
            return
        }
        if !checkAuth(r) {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(401)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "type": "error",
                "error": map[string]interface{}{
                    "type":    "authentication_error",
                    "message": "Invalid or missing authentication token",
                },
            })
            return
        }
        next(w, r)
    }
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// ── dashboard login session ─────────────────────────────────────────────
// Stateless signed cookie so the browser doesn't need to resend the raw
// token on every visit after a successful login. Value is "<exp>.<hmac>";
// the HMAC key is derived from AUTH_TOKEN, so it's unforgeable without
// knowing the token and automatically invalid if the token is rotated.
const dashSessionCookie = "qb_dash_session"
const dashSessionTTL = 12 * time.Hour

// dashboardSecret returns the credential that unlocks the "/" login form:
// DASHBOARD_PASSWORD if set, otherwise AUTH_TOKEN so a single-secret setup
// still works without extra configuration.
func dashboardSecret() string {
    if config.Auth.DashboardPassword != "" {
        return config.Auth.DashboardPassword
    }
    return config.Auth.Token
}

func dashSessionSign(exp int64) string {
    mac := hmac.New(sha256.New, []byte("qbridge-dash|"+dashboardSecret()))
    mac.Write([]byte(strconv.FormatInt(exp, 10)))
    return hex.EncodeToString(mac.Sum(nil))
}

func dashSessionValid(value string) bool {
    parts := strings.SplitN(value, ".", 2)
    if len(parts) != 2 {
        return false
    }
    exp, err := strconv.ParseInt(parts[0], 10, 64)
    if err != nil || time.Now().Unix() > exp {
        return false
    }
    expected := dashSessionSign(exp)
    return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func dashRequestIsHTTPS(r *http.Request) bool {
    if r.TLS != nil {
        return true
    }
    // Railway (and most PaaS) terminate TLS at the edge and proxy plain
    // HTTP to the app, so trust the standard forwarded-proto header.
    return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setDashSessionCookie(w http.ResponseWriter, r *http.Request) {
    exp := time.Now().Add(dashSessionTTL).Unix()
    http.SetCookie(w, &http.Cookie{
        Name:     dashSessionCookie,
        Value:    strconv.FormatInt(exp, 10) + "." + dashSessionSign(exp),
        Path:     "/",
        HttpOnly: true,
        Secure:   dashRequestIsHTTPS(r),
        SameSite: http.SameSiteStrictMode,
        MaxAge:   int(dashSessionTTL.Seconds()),
    })
}

func hasDashSession(r *http.Request) bool {
    c, err := r.Cookie(dashSessionCookie)
    if err != nil {
        return false
    }
    return dashSessionValid(c.Value)
}

// dashboardPasswordOK does a constant-time comparison of the submitted
// login-form password against dashboardSecret() (DASHBOARD_PASSWORD, or
// AUTH_TOKEN as fallback).
func dashboardPasswordOK(password string) bool {
    want := []byte(dashboardSecret())
    if len(want) == 0 {
        return false
    }
    return subtle.ConstantTimeCompare([]byte(password), want) == 1
}

// dashboardAuthed reports whether the request already carries the same
// credentials as every other protected route (Authorization/x-api-key
// header, or a "?token=" query param) — lets curl/automation skip the
// login form entirely.
func dashboardAuthed(r *http.Request) bool {
    if checkAuth(r) {
        return true
    }
    return config.Auth.Enabled && r.URL.Query().Get("token") == config.Auth.Token
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }
    if config.Server.DisableDashboard {
        http.NotFound(w, r)
        return
    }
    if !config.Auth.Enabled {
        serveDashboard(w, r)
        return
    }
    // Already authenticated: via header/query token (automation) or via an
    // existing login-form session cookie (browser).
    if dashboardAuthed(r) || hasDashSession(r) {
        serveDashboard(w, r)
        return
    }
    // Login-form submission.
    if r.Method == http.MethodPost {
        if err := r.ParseForm(); err == nil && dashboardPasswordOK(r.FormValue("password")) {
            setDashSessionCookie(w, r)
            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }
        serveDashboardLogin(w, r, true)
        return
    }
    // No credentials at all yet: show the password gate instead of the
    // panel. The panel embeds the live AUTH_TOKEN in its HTML, so it must
    // never render for an unauthenticated visitor.
    serveDashboardLogin(w, r, false)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
    session.mu.Lock()
    var userIDPreview interface{}
    if session.UserID != "" {
        uid := session.UserID
        if len(uid) > 8 {
            uid = uid[:8]
        }
        userIDPreview = uid + "..."
    }
    features := session.Features
    initialized := session.Initialized
    session.mu.Unlock()

    body := map[string]interface{}{
        "connected":   initialized,
        "userName":    session.UserName,
        "userId":      userIDPreview,
        "features":    features,
        "mode":        "guest",
    }
    if accounts != nil {
        body["mode"] = "accounts"
        body["accountPool"] = map[string]interface{}{
            "enabled": true,
            "size":    accounts.Len(),
            "healthy": accounts.HealthyCount(),
        }
        body["accounts"] = accounts.StatusJSON()
    } else {
        body["accountPool"] = map[string]interface{}{
            "enabled": false,
            "size":    0,
            "healthy": 0,
        }
    }

    writeJSON(w, 200, body)
}

