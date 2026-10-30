package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type oidcHarness struct {
	accountPath    string
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
	previousSettings := authn.DefaultSettings
	authn.DefaultSettings = authn.NewSettingsStore(filepath.Join(t.TempDir(), "authentication.json"))
	t.Cleanup(func() { authn.DefaultSettings = previousSettings })
	accountPath := filepath.Join(t.TempDir(), "pwd")
	store := authn.NewStoreWithRecovery(accountPath, authn.DefaultSettings)
	restore := useTestStore(store)
	t.Cleanup(restore)
	if _, ok, err := store.Authenticate("admin", "admin"); err != nil || !ok {
		t.Fatalf("initialize account: %v", err)
	}
	if err := store.Create("alice", "alice-password", authn.RoleUser, authn.PermConsoleView); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h := &oidcHarness{accountPath: accountPath, subject: "alice-id", service: NewService()}
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
	for i := range settings.OIDC.Bindings {
		user, getErr := store.Get(settings.OIDC.Bindings[i].Username)
		if getErr != nil {
			t.Fatal(getErr)
		}
		settings.OIDC.Bindings[i].AccountID = user.ID
	}
	h.settings, err = authn.DefaultSettings.Save(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	h.router = gin.New()
	if err := h.router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	h.router.POST("/login", h.service.Login)
	h.router.GET("/methods", h.service.LoginMethods)
	h.router.GET("/api/auth/oidc/login", h.service.OIDCLogin)
	h.router.GET(authn.OIDCCallbackPath, h.service.OIDCCallback)
	api := h.router.Group("/").Use(middleware.CheckToken())
	api.GET("/account", h.service.GetAccount)
	api.GET("/password", h.service.IsPasswordUpdated)
	api.POST("/password", h.service.ChangePassword)
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

func saveOIDCSettings(t *testing.T, h *oidcHarness, settings authn.Settings, cookie *http.Cookie) (authn.Settings, *http.Cookie) {
	t.Helper()
	r := requestJSONRecorder(h.router, http.MethodPut, "/settings", settings, cookie)
	var rsp struct {
		Code int
		Data struct{ Settings authn.Settings }
	}
	if err := json.Unmarshal(r.Body.Bytes(), &rsp); err != nil || rsp.Code != 0 {
		t.Fatalf("save settings: %s %v", r.Body, err)
	}
	return rsp.Data.Settings, sessionCookie(r)
}

func TestOIDCDeletedAccountCannotAttachToReusedUsername(t *testing.T) {
	h := newOIDCHarness(t)
	state, flow := h.start(t)
	oldSession := sessionCookie(h.callback(state, flow))
	if oldSession == nil {
		t.Fatal("initial OIDC login failed")
	}
	oldUser, err := authn.DefaultStore.Get("alice")
	if err != nil {
		t.Fatal(err)
	}
	adminCookie := loginCookie(t, h.router, "admin", "admin")
	if err = authn.DefaultStore.Delete("admin", "alice"); err != nil {
		t.Fatal(err)
	}
	if err = authn.DefaultStore.Create("alice", "replacement-password", authn.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	replacement, err := authn.DefaultStore.Get("alice")
	if err != nil || replacement.ID == oldUser.ID {
		t.Fatalf("reused account identity: %+v %v", replacement, err)
	}
	if requestJSON(h.router, http.MethodGet, "/account", nil, oldSession) != http.StatusUnauthorized {
		t.Fatal("old session survived account recreation")
	}
	// Challenge the shared middleware independently of callback admission.
	minted, err := middleware.GenerateSessionJWT("alice", replacement.TokenVersion, authn.MethodOIDC, h.settings.Revision, "alice-id", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if requestJSON(h.router, http.MethodGet, "/account", nil, &http.Cookie{Name: middleware.CookieName, Value: minted}) != http.StatusUnauthorized {
		t.Fatal("middleware accepted stale account binding")
	}
	state, flow = h.start(t)
	if sessionCookie(h.callback(state, flow)) != nil {
		t.Fatal("old subject logged into replacement administrator")
	}
	// Neither omitted IDs nor a forged replacement ID may reattach a saved link.
	next := h.settings
	next.OIDC.Bindings = append([]authn.OIDCBinding{}, next.OIDC.Bindings...)
	next.OIDC.Bindings[0].AccountID = replacement.ID
	next.OIDC.Bindings[1].AccountID = ""
	next, adminCookie = saveOIDCSettings(t, h, next, adminCookie)
	if next.OIDC.Bindings[0].AccountID != oldUser.ID {
		t.Fatal("settings round trip rebound deleted account")
	}
	state, flow = h.start(t)
	if sessionCookie(h.callback(state, flow)) != nil {
		t.Fatal("round trip restored stale identity")
	}
	// Relinking requires an explicit removal, a save, and then a new link.
	next.OIDC.Bindings = next.OIDC.Bindings[1:]
	next, adminCookie = saveOIDCSettings(t, h, next, adminCookie)
	next.OIDC.Bindings = append(next.OIDC.Bindings, authn.OIDCBinding{Subject: "alice-id", Username: "alice"})
	next, _ = saveOIDCSettings(t, h, next, adminCookie)
	if next.OIDC.Bindings[1].AccountID != replacement.ID {
		t.Fatal("deliberate relink did not pin replacement")
	}
	state, flow = h.start(t)
	if sessionCookie(h.callback(state, flow)) == nil {
		t.Fatal("deliberately relinked identity could not sign in")
	}
}

func TestBOOTAccountResetRestoresLocalLoginAndInvalidatesOIDC(t *testing.T) {
	h := newOIDCHarness(t)
	h.settings.LocalEnabled, h.settings.MCPKeyEnabled = false, false
	var err error
	h.settings, err = authn.DefaultSettings.Save(h.settings, false)
	if err != nil {
		t.Fatal(err)
	}
	h.subject = "admin-id"
	state, flow := h.start(t)
	oldSession := sessionCookie(h.callback(state, flow))
	if oldSession == nil {
		t.Fatal("OIDC-only login failed")
	}
	if err = os.Remove(h.accountPath); err != nil {
		t.Fatal(err)
	}
	// This is exactly the account-file operation performed by the existing BOOT firmware.
	methods := requestJSONRecorder(h.router, http.MethodGet, "/methods", nil, nil)
	if !strings.Contains(methods.Body.String(), `"localEnabled":true`) {
		t.Fatalf("BOOT left local login disabled: %s", methods.Body)
	}
	if requestJSON(h.router, http.MethodGet, "/account", nil, oldSession) != http.StatusUnauthorized {
		t.Fatal("OIDC session survived physical reset")
	}
	if loginCookie(t, h.router, "admin", "admin") == nil {
		t.Fatal("default recovery login failed")
	}
	recovered, err := authn.DefaultSettings.Get()
	if err != nil || !recovered.LocalEnabled || recovered.MCPKeyEnabled || !recovered.OIDC.Enabled || len(recovered.OIDC.Bindings) != 0 || recovered.OIDC.ClientSecret != "provider-secret" || recovered.Revision == h.settings.Revision {
		t.Fatalf("incorrect recovery state: %+v %v", recovered, err)
	}
	state, flow = h.start(t)
	if sessionCookie(h.callback(state, flow)) != nil {
		t.Fatal("old OIDC subject attached to reset owner")
	}
	restarted := authn.NewStoreWithRecovery(h.accountPath, authn.DefaultSettings)
	if err = restarted.Initialize(); err != nil {
		t.Fatal(err)
	}
	again, err := authn.DefaultSettings.Get()
	if err != nil || again.Revision != recovered.Revision {
		t.Fatalf("recovery repeated on restart: %+v %v", again, err)
	}
}

func TestOIDCPasswordWarningAndChangeFollowLocalAvailability(t *testing.T) {
	h := newOIDCHarness(t)
	h.subject = "admin-id"
	state, flow := h.start(t)
	cookie := sessionCookie(h.callback(state, flow))
	r := requestJSONRecorder(h.router, http.MethodGet, "/password", nil, cookie)
	if !strings.Contains(r.Body.String(), `"isUpdated":false`) {
		t.Fatalf("OIDC hid default-password warning: %s", r.Body)
	}
	account := requestJSONRecorder(h.router, http.MethodGet, "/account", nil, cookie)
	if !strings.Contains(account.Body.String(), `"localEnabled":true`) {
		t.Fatalf("missing password action state: %s", account.Body)
	}
	r = requestJSONRecorder(h.router, http.MethodPost, "/password", map[string]string{"currentPassword": encryptForRequest("incorrect"), "password": encryptForRequest("replacement-password")}, cookie)
	if !strings.Contains(r.Body.String(), `"code":-3`) {
		t.Fatalf("OIDC bypassed current-password check: %s", r.Body)
	}
	original := systemPasswordUpdater
	systemPasswordUpdater = func(string) error { return nil }
	t.Cleanup(func() { systemPasswordUpdater = original })
	r = requestJSONRecorder(h.router, http.MethodPost, "/password", map[string]string{"currentPassword": encryptForRequest("admin"), "password": encryptForRequest("replacement-password")}, cookie)
	if !strings.Contains(r.Body.String(), `"code":0`) {
		t.Fatalf("OIDC password change failed: %s", r.Body)
	}
	state, flow = h.start(t)
	cookie = sessionCookie(h.callback(state, flow))
	if cookie == nil {
		t.Fatal("password change broke immutable OIDC binding")
	}
	r = requestJSONRecorder(h.router, http.MethodGet, "/password", nil, cookie)
	if !strings.Contains(r.Body.String(), `"isUpdated":true`) {
		t.Fatalf("changed password still warned: %s", r.Body)
	}
	h.settings.LocalEnabled = false
	var err error
	h.settings, err = authn.DefaultSettings.Save(h.settings, false)
	if err != nil {
		t.Fatal(err)
	}
	state, flow = h.start(t)
	cookie = sessionCookie(h.callback(state, flow))
	r = requestJSONRecorder(h.router, http.MethodGet, "/password", nil, cookie)
	if !strings.Contains(r.Body.String(), `"isUpdated":true`) {
		t.Fatalf("disabled local login still warned: %s", r.Body)
	}
	account = requestJSONRecorder(h.router, http.MethodGet, "/account", nil, cookie)
	if !strings.Contains(account.Body.String(), `"localEnabled":false`) {
		t.Fatalf("password action remained available: %s", account.Body)
	}
}

func TestOIDCFloodCannotExhaustOtherSourcesOrSpoofForwardingHeaders(t *testing.T) {
	h := newOIDCHarness(t)
	for i := 0; i < oidcMaxFlows+10; i++ {
		request := jsonRequest(http.MethodGet, "/api/auth/oidc/login", nil)
		request.RemoteAddr = "192.0.2.1:12345"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i%255))
		request.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i%255))
		h.router.ServeHTTP(httptest.NewRecorder(), request)
	}
	if len(h.service.flows) != oidcMaxFlowsPerSource || len(h.service.flowStarts) != 1 {
		t.Fatalf("source quota bypassed: %d flows / %d sources", len(h.service.flows), len(h.service.flowStarts))
	}
	request := jsonRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	request.RemoteAddr = "192.0.2.2:23456"
	r := httptest.NewRecorder()
	h.router.ServeHTTP(r, request)
	location, err := url.Parse(r.Header().Get("Location"))
	if err != nil || location.Query().Get("response_type") != "code" {
		t.Fatalf("other source denied: %s", r.Header().Get("Location"))
	}
	h.nonce, h.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
	var flowCookie *http.Cookie
	for _, cookie := range r.Result().Cookies() {
		if cookie.Name == oidcCookieName {
			flowCookie = cookie
		}
	}
	if sessionCookie(h.callback(location.Query().Get("state"), flowCookie)) == nil {
		t.Fatal("other source could not complete login")
	}
	if len(h.service.flows) != oidcMaxFlowsPerSource {
		t.Fatal("callback did not release its pending slot")
	}
}

func TestOIDCAdmissionRateExpiryReplacementAndBookkeepingBounds(t *testing.T) {
	s := NewService()
	now := time.Now()
	flow := oidcFlow{source: "one-source", expires: now.Add(oidcFlowDuration)}
	previous := ""
	for i := 0; i < oidcMaxStartsPerMinute; i++ {
		state := fmt.Sprint(i)
		if !s.reserveOIDCFlow(state, previous, flow, now) {
			t.Fatalf("normal browser retry %d rejected", i)
		}
		previous = state
	}
	if s.reserveOIDCFlow("excess", previous, flow, now) {
		t.Fatal("start-rate limit bypassed with cookie replacement")
	}
	if _, ok := s.flows[previous]; !ok {
		t.Fatal("rejected retry destroyed an existing browser flow")
	}
	if !s.reserveOIDCFlow("later", "", oidcFlow{source: flow.source, expires: now.Add(2 * oidcFlowDuration)}, now.Add(oidcFlowDuration)) {
		t.Fatal("expired flow/window did not release quota")
	}
	if len(s.flows) != 1 || len(s.flowStarts) != 1 {
		t.Fatal("expired state leaked")
	}
	// Remember completed attempts only for one minute, with a fixed memory cap.
	s = NewService()
	for i := 0; i < oidcMaxStartSources; i++ {
		state := fmt.Sprint(i)
		if !s.reserveOIDCFlow(state, "", oidcFlow{source: state, expires: now.Add(oidcFlowDuration)}, now) {
			t.Fatal("source bookkeeping filled early")
		}
		delete(s.flows, state)
	}
	if s.reserveOIDCFlow("overflow", "", flow, now) || len(s.flowStarts) != oidcMaxStartSources {
		t.Fatal("source bookkeeping exceeded cap")
	}
	if !s.reserveOIDCFlow("recovered", "", flow, now.Add(time.Minute)) || len(s.flowStarts) != 1 {
		t.Fatal("expired source bookkeeping did not recover")
	}
}

func TestAuthenticationDisabledDoesNotRequireValidAccountStorage(t *testing.T) {
	h := newOIDCHarness(t)
	conf := config.GetInstance()
	conf.Authentication = "disable"
	if err := os.WriteFile(h.accountPath, []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousSettings := authn.DefaultSettings
	path := filepath.Join(t.TempDir(), "authentication.json")
	if err := os.WriteFile(path, []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	authn.DefaultSettings = authn.NewSettingsStore(path)
	t.Cleanup(func() { authn.DefaultSettings = previousSettings })
	r := requestJSONRecorder(h.router, http.MethodGet, "/account", nil, nil)
	if !strings.Contains(r.Body.String(), `"code":0`) || !strings.Contains(r.Body.String(), `"role":"admin"`) {
		t.Fatalf("disabled authentication depended on account storage: %s", r.Body)
	}
	r = requestJSONRecorder(h.router, http.MethodGet, "/methods", nil, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"authenticationDisabled":true`) {
		t.Fatalf("disabled authentication depended on method storage: %s", r.Body)
	}
	conf.Authentication = "enable"
	if requestJSON(h.router, http.MethodGet, "/account", nil, nil) != http.StatusUnauthorized {
		t.Fatal("enabled authentication was bypassed")
	}
	if requestJSON(h.router, http.MethodGet, "/methods", nil, nil) != http.StatusServiceUnavailable {
		t.Fatal("enabled authentication ignored corrupt accounts")
	}
}

func TestOIDCAdmissionSeparatesClientsBehindTrustedProxy(t *testing.T) {
	h := newOIDCHarness(t)
	if err := h.router.SetTrustedProxies([]string{"192.0.2.10/32"}); err != nil {
		t.Fatal(err)
	}
	start := func(realClient string) *httptest.ResponseRecorder {
		request := jsonRequest(http.MethodGet, "/api/auth/oidc/login", nil)
		request.RemoteAddr = "192.0.2.10:12345"
		// Untrusted prefixes cannot change the actual last client before the proxy.
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d, %s", len(h.service.flows), realClient))
		r := httptest.NewRecorder()
		h.router.ServeHTTP(r, request)
		return r
	}
	for i := 0; i < oidcMaxFlowsPerSource+1; i++ {
		start("198.51.100.1")
	}
	r := start("198.51.100.2")
	location, err := url.Parse(r.Header().Get("Location"))
	if err != nil || location.Query().Get("response_type") != "code" {
		t.Fatalf("one client denied another behind trusted proxy: %s", r.Header().Get("Location"))
	}
	if len(h.service.flows) != oidcMaxFlowsPerSource+1 || len(h.service.flowStarts) != 2 {
		t.Fatalf("trusted proxy did not preserve client budgets: %d / %d", len(h.service.flows), len(h.service.flowStarts))
	}
	h.nonce, h.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
	var flowCookie *http.Cookie
	for _, cookie := range r.Result().Cookies() {
		if cookie.Name == oidcCookieName {
			flowCookie = cookie
		}
	}
	if sessionCookie(h.callback(location.Query().Get("state"), flowCookie)) == nil {
		t.Fatal("proxied client could not complete login")
	}
}

func TestOIDCOnlyDoesNotWarnAboutUnusedDefaultWebPassword(t *testing.T) {
	h := newOIDCHarness(t)
	h.settings.LocalEnabled = false
	var err error
	h.settings, err = authn.DefaultSettings.Save(h.settings, false)
	if err != nil {
		t.Fatal(err)
	}
	h.subject = "admin-id"
	state, flow := h.start(t)
	cookie := sessionCookie(h.callback(state, flow))
	r := requestJSONRecorder(h.router, http.MethodGet, "/password", nil, cookie)
	if !strings.Contains(r.Body.String(), `"isUpdated":true`) {
		t.Fatalf("unused local password blocked OIDC-only use: %s", r.Body)
	}
}

func TestOIDCTrustedProxyNormalizesEquivalentIPv6Addresses(t *testing.T) {
	h := newOIDCHarness(t)
	if err := h.router.SetTrustedProxies([]string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < oidcMaxFlowsPerSource+1; i++ {
		request := jsonRequest(http.MethodGet, "/api/auth/oidc/login", nil)
		request.RemoteAddr = "192.0.2.10:12345"
		// Use equivalent full and compressed forms.
		addresses := []string{"2001:db8::1", "2001:db8:0:0:0:0:0:1", "2001:0db8::0001"}
		request.Header.Set("X-Forwarded-For", addresses[i%len(addresses)])
		h.router.ServeHTTP(httptest.NewRecorder(), request)
	}
	if len(h.service.flows) != oidcMaxFlowsPerSource || len(h.service.flowStarts) != 1 {
		t.Fatal("IPv6 spelling bypassed source quota")
	}
}
