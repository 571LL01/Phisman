package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	csrfCookieName = "__Host-siren-csrf"
	csrfFieldName  = "csrf_token"
	csrfBytes      = 32
)

// newCSRFToken generates a 256-bit random CSRF token and returns both the
// cookie value and the HMAC-signed form field value.
//
// The double-submit cookie pattern:
//   - The browser receives a cookie csrfCookieName=<raw>.
//   - The form embeds csrf_token=HMAC(raw).
//   - On POST, the server re-derives HMAC(cookie) and compares in constant
//     time with the submitted field.
//
// A cross-origin attacker can forge the cookie (if the domain is permissive)
// but cannot read it back to derive the HMAC, so the signed form field cannot
// be forged. Same-site cookies (SameSite=Lax on the session cookie) already
// block cross-site POST in modern browsers; this layer defends older browsers.
func newCSRFToken(secret []byte) (cookieVal, fieldVal string, err error) {
	raw := make([]byte, csrfBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("admin: csrf token: %w", err)
	}
	cookieVal = base64.RawURLEncoding.EncodeToString(raw)
	fieldVal = signCSRF(cookieVal, secret)
	return cookieVal, fieldVal, nil
}

func signCSRF(cookieVal string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(cookieVal))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// csrfCookieKey returns the cookie name for the given secure flag.
// When secure is false (HTTP) the __Host- prefix is dropped because
// the browser requires Secure=true for __Host- cookies.
func csrfCookieKey(secure bool) string {
	if !secure {
		return "siren-csrf-dev"
	}
	return csrfCookieName
}

// setCSRFCookie writes the CSRF cookie.
func setCSRFCookie(w http.ResponseWriter, cookieVal string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieKey(secure),
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: false, // must be readable by the form page (same-origin)
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCSRFCookie expires the CSRF cookie on logout.
func clearCSRFCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieKey(secure),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// checkCSRF validates the double-submit token on a POST request.
// It reads the cookie, re-derives the HMAC, and compares in constant time.
func checkCSRF(r *http.Request, secret []byte, secure bool) bool {
	ck, err := r.Cookie(csrfCookieKey(secure))
	if err != nil || strings.TrimSpace(ck.Value) == "" {
		return false
	}
	submitted := strings.TrimSpace(r.FormValue(csrfFieldName))
	if submitted == "" {
		return false
	}
	want := signCSRF(ck.Value, secret)
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(want)) == 1
}

// IssueCSRF generates a CSRF token pair, sets the cookie on w, and returns the
// form field value. It is the exported entry point for handlers outside the
// admin package that render forms behind the same Guard.
func (c Config) IssueCSRF(w http.ResponseWriter) (fieldVal string, err error) {
	cookieVal, fieldVal, err := newCSRFToken(c.CSRFSecret)
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, cookieVal, c.SecureCookies)
	return fieldVal, nil
}

// loginPageHTML is the minimal HTML login form. It embeds the CSRF token in a
// hidden field. A production deployment would use a template engine and add
// branding; this is intentionally minimal so the package has no HTML file
// dependency and the token injection is explicit.
func loginPageHTML(csrfField string) string {
	return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIREN — Administration</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;
     font:16px/1.5 system-ui,sans-serif;background:#f4f4f5}
form{padding:2rem;border-radius:.5rem;background:#fff;
     box-shadow:0 1px 4px rgba(0,0,0,.12);min-width:20rem}
h1{margin:0 0 1.5rem;font-size:1.25rem}
label{display:block;font-size:.8rem;font-weight:600;margin:.75rem 0 .25rem}
input{width:100%;box-sizing:border-box;padding:.5rem .75rem;
      border:1px solid #d1d5db;border-radius:.375rem;font:inherit}
button{margin-top:1.25rem;width:100%;padding:.6rem;border:0;
       border-radius:.375rem;background:#1d4ed8;color:#fff;
       font:inherit;font-weight:700;cursor:pointer}
button:hover{background:#163ba6}
</style>
</head>
<body>
<form method="post" action="/admin/login">
<h1>Administration</h1>
<input type="hidden" name="` + csrfFieldName + `" value="` + csrfField + `">
<label for="p">Mot de passe</label>
<input type="password" id="p" name="password" autocomplete="current-password" required>
<label for="t">Code TOTP</label>
<input type="text" id="t" name="totp_code" inputmode="numeric" maxlength="6"
       autocomplete="one-time-code" spellcheck="false" required>
<button type="submit">Connexion</button>
</form>
</body>
</html>
`
}
