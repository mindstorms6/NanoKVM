package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type oidcHarness struct {
	router         *gin.Engine
	service        *Service
	settings       authn.Settings
	nonce          string
	challenge      string
	claims         func(jwt.MapClaims)
	subject        string
	exchanges      int
	wrongSignature bool
}

func newOIDCHarness(t *testing.T) *oidcHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := authn.NewStore(filepath.Join(t.TempDir(), "pwd"))
	restore := useTestStore(store)
	t.Cleanup(restore)
	if _, ok, err := store.Authenticate("admin", "admin"); err != nil || !ok {
		t.Fatalf("initialize account: %v", err)
	}
	if err := store.Create("alice", "alice-password", authn.RoleUser, authn.PermConsoleView); err != nil {
		t.Fatal(err)
	}
	previousSettings := authn.DefaultSettings
	authn.DefaultSettings = authn.NewSettingsStore(filepath.Join(t.TempDir(), "authentication.json"))
	t.Cleanup(func() { authn.DefaultSettings = previousSettings })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h := &oidcHarness{subject: "alice-id", service: NewService()}
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			h.exchanges++
			r.ParseForm()
			client, secret, ok := r.BasicAuth()
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || client != "nanokvm" || secret != "provider-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "one-use-code" || r.Form.Get("redirect_uri") != h.settings.OIDC.RedirectURL || base64.RawURLEncoding.EncodeToString(challenge[:]) != h.challenge {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			claims := jwt.MapClaims{"iss": issuer, "sub": h.subject, "aud": "nanokvm", "exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": h.nonce, "preferred_username": "admin"}
			if h.claims != nil {
				h.claims(claims)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test-key"
			signingKey := key
			if h.wrongSignature {
				signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			signed, signErr := token.SignedString(signingKey)
			if signErr != nil {
				t.Error(signErr)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-access-token", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = provider.URL
	t.Cleanup(provider.Close)
	previousClient := oidcHTTPClient
	oidcHTTPClient = provider.Client()
	oidcHTTPClient.Timeout = 2 * time.Second
	t.Cleanup(func() { oidcHTTPClient = previousClient })
	settings := authn.DefaultAuthSettings()
	settings.OIDC = authn.OIDCSettings{Enabled: true, DisplayName: "Keycloak", Issuer: issuer, ClientID: "nanokvm", ClientSecret: "provider-secret", RedirectURL: "https://kvm.example" + authn.OIDCCallbackPath, Scopes: []string{"openid", "profile"}, Bindings: []authn.OIDCBinding{{Subject: "alice-id", Username: "alice"}, {Subject: "admin-id", Username: "admin"}}}
	h.settings, err = authn.DefaultSettings.Save(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	h.router = gin.New()
	h.router.POST("/login", h.service.Login)
	h.router.GET("/methods", h.service.LoginMethods)
	h.router.GET("/api/auth/oidc/login", h.service.OIDCLogin)
	h.router.GET(authn.OIDCCallbackPath, h.service.OIDCCallback)
	api := h.router.Group("/").Use(middleware.CheckToken())
	api.GET("/account", h.service.GetAccount)
	admin := h.router.Group("/").Use(middleware.CheckToken(), middleware.RequireRole(authn.RoleAdmin))
	admin.GET("/settings", h.service.GetSettings)
	admin.PUT("/settings", h.service.SetSettings)
	return h
}

func (h *oidcHarness) start(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	r := requestJSONRecorder(h.router, http.MethodGet, "/api/auth/oidc/login", nil, nil)
	location, err := url.Parse(r.Header().Get("Location"))
	if err != nil || location.Query().Get("response_type") != "code" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid authorization redirect: %s %v", r.Body, err)
	}
	h.nonce, h.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
	state := location.Query().Get("state")
	if state == "" || h.nonce == "" || h.challenge == "" {
		t.Fatal("missing CSRF, nonce or PKCE parameter")
	}
	for _, cookie := range r.Result().Cookies() {
		if cookie.Name == oidcCookieName {
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
				t.Fatalf("unsafe flow cookie: %+v", cookie)
			}
			return state, cookie
		}
	}
	t.Fatal("missing flow cookie")
	return "", nil
}

func (h *oidcHarness) callback(state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	return requestJSONRecorder(h.router, http.MethodGet, authn.OIDCCallbackPath+"?state="+url.QueryEscape(state)+"&code=one-use-code", nil, cookie)
}

func sessionCookie(r *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range r.Result().Cookies() {
		if cookie.Name == middleware.CookieName && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}

func TestOIDCLoginUsesLinkedAccountAndRevocation(t *testing.T) {
	h := newOIDCHarness(t)
	state, flowCookie := h.start(t)
	r := h.callback(state, flowCookie)
	cookie := sessionCookie(r)
	if r.Code != http.StatusOK || cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("OIDC login failed: %d %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "provider-access-token") || strings.Contains(r.Body.String(), "provider-secret") {
		t.Fatal("provider credentials leaked")
	}
	token, err := middleware.ParseJWT(cookie.Value)
	if err != nil || token.Username != "alice" || token.AuthMethod != "oidc" || token.OIDCSubject != "alice-id" || time.Until(token.ExpiresAt.Time) > 10*time.Minute {
		t.Fatalf("incorrect local session: %+v %v", token, err)
	}
	r = requestJSONRecorder(h.router, http.MethodGet, "/account", nil, cookie)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"role":"user"`) || !strings.Contains(r.Body.String(), `"console.view"`) {
		t.Fatalf("local permissions lost: %s", r.Body)
	}
	if requestJSON(h.router, http.MethodGet, "/settings", nil, cookie) != http.StatusForbidden {
		t.Fatal("OIDC user gained admin access")
	}
	if sessionCookie(h.callback(state, flowCookie)) != nil || h.exchanges != 1 {
		t.Fatal("callback replay accepted")
	}
	_, _, err = authn.DefaultStore.Update("admin", "alice", authn.UserPatch{Enabled: boolPointer(false)})
	if err != nil {
		t.Fatal(err)
	}
	if requestJSON(h.router, http.MethodGet, "/account", nil, cookie) != http.StatusUnauthorized {
		t.Fatal("disabled account kept OIDC access")
	}
}

func boolPointer(value bool) *bool { return &value }

func TestOIDCRejectsInvalidTokens(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*oidcHarness)
	}{
		{"issuer", func(h *oidcHarness) { h.claims = func(c jwt.MapClaims) { c["iss"] = "https://other.example" } }},
		{"audience", func(h *oidcHarness) { h.claims = func(c jwt.MapClaims) { c["aud"] = "another-client" } }},
		{"authorized party", func(h *oidcHarness) { h.claims = func(c jwt.MapClaims) { c["azp"] = "another-client" } }},
		{"multiple audiences without authorized party", func(h *oidcHarness) {
			h.claims = func(c jwt.MapClaims) { c["aud"] = []string{"nanokvm", "another-client"} }
		}},
		{"expired", func(h *oidcHarness) {
			h.claims = func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() }
		}},
		{"nonce", func(h *oidcHarness) { h.claims = func(c jwt.MapClaims) { c["nonce"] = "wrong-nonce" } }},
		{"signature", func(h *oidcHarness) { h.wrongSignature = true }},
		{"unlinked subject", func(h *oidcHarness) { h.subject = "unlinked-user-with-admin-name" }},
		{"PKCE", func(h *oidcHarness) { h.challenge = "wrong-challenge" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newOIDCHarness(t)
			state, cookie := h.start(t)
			tc.modify(h)
			r := h.callback(state, cookie)
			if r.Code != http.StatusFound || sessionCookie(r) != nil || !strings.HasPrefix(r.Header().Get("Location"), "/#/auth/login?oidcError=") {
				t.Fatalf("invalid login accepted: %d %s", r.Code, r.Body)
			}
		})
	}
}

func TestOIDCCallbackRequiresBrowserStateAndCurrentSettings(t *testing.T) {
	h := newOIDCHarness(t)
	state, cookie := h.start(t)
	if sessionCookie(h.callback(state, nil)) != nil || h.exchanges != 0 {
		t.Fatal("callback accepted without browser cookie")
	}
	wrong := *cookie
	wrong.Value = "wrong-state"
	if sessionCookie(h.callback(state, &wrong)) != nil || h.exchanges != 0 {
		t.Fatal("callback accepted with wrong browser cookie")
	}
	h.service.mutex.Lock()
	flow := h.service.flows[state]
	flow.expires = time.Now().Add(-time.Minute)
	h.service.flows[state] = flow
	h.service.mutex.Unlock()
	if sessionCookie(h.callback(state, cookie)) != nil || h.exchanges != 0 {
		t.Fatal("expired flow accepted")
	}
	state, cookie = h.start(t)
	_, err := authn.DefaultSettings.Save(h.settings, false)
	if err != nil {
		t.Fatal(err)
	}
	if sessionCookie(h.callback(state, cookie)) != nil || h.exchanges != 0 {
		t.Fatal("flow survived settings change")
	}
}

func TestSettingsOIDCOnlyRequiresProvenAdminLogin(t *testing.T) {
	h := newOIDCHarness(t)
	localCookie := loginCookie(t, h.router, "admin", "admin")
	r := requestJSONRecorder(h.router, http.MethodGet, "/settings", nil, localCookie)
	if strings.Contains(r.Body.String(), "provider-secret") || !strings.Contains(r.Body.String(), `"clientSecretConfigured":true`) {
		t.Fatalf("unsafe settings response: %s", r.Body)
	}
	public := requestJSONRecorder(h.router, http.MethodGet, "/methods", nil, nil)
	if strings.Contains(public.Body.String(), "bindings") || strings.Contains(public.Body.String(), "clientId") {
		t.Fatal("public endpoint leaked provider configuration")
	}
	next := h.settings
	next.LocalEnabled = false
	r = requestJSONRecorder(h.router, http.MethodPut, "/settings", next, localCookie)
	if !strings.Contains(r.Body.String(), "sign in as an OIDC administrator") {
		t.Fatalf("lockout guard missing: %s", r.Body)
	}
	h.subject = "admin-id"
	state, flowCookie := h.start(t)
	oidcCookie := sessionCookie(h.callback(state, flowCookie))
	if oidcCookie == nil {
		t.Fatal("admin OIDC login failed")
	}
	request := jsonRequest(http.MethodPut, "/settings", next)
	request.AddCookie(oidcCookie)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	r = httptest.NewRecorder()
	h.router.ServeHTTP(r, request)
	if r.Code != http.StatusForbidden {
		t.Fatal("cross-site settings write accepted")
	}
	r = requestJSONRecorder(h.router, http.MethodPut, "/settings", next, oidcCookie)
	var response struct {
		Code int
		Data struct{ Settings authn.Settings }
	}
	if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil || response.Code != 0 {
		t.Fatalf("OIDC-only save failed: %s %v", r.Body, err)
	}
	renewed := sessionCookie(r)
	if renewed == nil || requestJSON(h.router, http.MethodGet, "/account", nil, renewed) != http.StatusOK {
		t.Fatal("saving administrator lost access")
	}
	if requestJSON(h.router, http.MethodGet, "/account", nil, localCookie) != http.StatusUnauthorized || requestJSON(h.router, http.MethodGet, "/account", nil, oidcCookie) != http.StatusUnauthorized {
		t.Fatal("previous sessions survived settings change")
	}
	if requestJSON(h.router, http.MethodPost, "/login", map[string]string{"username": "admin", "password": encryptForRequest("admin")}, nil) != http.StatusForbidden {
		t.Fatal("disabled password method still accepts logins")
	}
	next = response.Data.Settings
	next.OIDC.Enabled = false
	r = requestJSONRecorder(h.router, http.MethodPut, "/settings", next, renewed)
	if !strings.Contains(r.Body.String(), "at least one browser login") {
		t.Fatalf("all methods disabled: %s", r.Body)
	}
	next.LocalEnabled = true
	r = requestJSONRecorder(h.router, http.MethodPut, "/settings", next, renewed)
	if !strings.Contains(r.Body.String(), `"code":0`) {
		t.Fatalf("cannot restore local login: %s", r.Body)
	}
	if sessionCookie(h.callback("anything", flowCookie)) != nil {
		t.Fatal("disabled OIDC accepted")
	}
	if sessionCookie(requestJSONRecorder(h.router, http.MethodPost, "/login", map[string]string{"username": "admin", "password": encryptForRequest("admin")}, nil)) == nil {
		t.Fatal("restored local login failed")
	}
}
