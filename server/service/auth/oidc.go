package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const oidcCookieName = "nano-kvm-oidc-state"
const oidcFlowDuration = 5 * time.Minute

type oidcFlow struct {
	nonce    string
	verifier string
	revision string
	expires  time.Time
}

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

func (s *Service) discoverProvider(settings authn.Settings) (*oidc.Provider, error) {
	// Discovery depends only on the issuer. Key rotation is handled by go-oidc's
	// remote key set; client IDs, secrets and redirect URLs are never cached.
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.provider != nil && s.providerIssuer == settings.OIDC.Issuer {
		return s.provider, nil
	}
	ctx := oidc.ClientContext(context.Background(), oidcHTTPClient)
	provider, err := oidc.NewProvider(ctx, settings.OIDC.Issuer)
	if err != nil {
		return nil, err
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		if err = authn.ValidateOIDCURL(raw, false); err != nil {
			return nil, err
		}
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err = provider.Claims(&metadata); err != nil {
		return nil, err
	}
	if err = authn.ValidateOIDCURL(metadata.JWKSURL, false); err != nil {
		return nil, err
	}
	s.provider, s.providerIssuer = provider, settings.OIDC.Issuer
	return provider, nil
}

func oauthConfig(settings authn.Settings, provider *oidc.Provider) oauth2.Config {
	scopes := []string{oidc.ScopeOpenID}
	for _, scope := range settings.OIDC.Scopes {
		if scope != "" && scope != oidc.ScopeOpenID && scope != "offline_access" {
			scopes = append(scopes, scope)
		}
	}
	return oauth2.Config{
		ClientID: settings.OIDC.ClientID, ClientSecret: settings.OIDC.ClientSecret,
		RedirectURL: settings.OIDC.RedirectURL, Endpoint: provider.Endpoint(), Scopes: scopes,
	}
}

func (s *Service) OIDCLogin(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	settings, err := authn.DefaultSettings.Get()
	if err != nil || !settings.OIDC.Enabled || config.GetInstance().Authentication == "disable" {
		s.oidcFailure(c)
		return
	}
	provider, err := s.discoverProvider(settings)
	if err != nil {
		s.oidcFailure(c)
		return
	}
	state, nonce, verifier := rand.Text(), rand.Text(), oauth2.GenerateVerifier()
	now := time.Now()
	s.mutex.Lock()
	for key, flow := range s.flows {
		if !flow.expires.After(now) {
			delete(s.flows, key)
		}
	}
	if len(s.flows) >= 512 {
		s.mutex.Unlock()
		s.oidcFailure(c)
		return
	}
	s.flows[state] = oidcFlow{nonce: nonce, verifier: verifier, revision: settings.Revision, expires: now.Add(oidcFlowDuration)}
	s.mutex.Unlock()
	setOIDCCookie(c, state, int(oidcFlowDuration.Seconds()), settings)
	oauth := oauthConfig(settings, provider)
	c.Redirect(http.StatusFound, oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
}

func setOIDCCookie(c *gin.Context, state string, maxAge int, settings authn.Settings) {
	// Lax is required for the cross-site top-level GET back from Keycloak. The
	// normal application session remains HttpOnly and SameSite=Strict.
	secure := strings.HasPrefix(settings.OIDC.RedirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcCookieName, state, maxAge, "/api/auth/oidc", "", secure, true)
}

func (s *Service) OIDCCallback(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	settings, err := authn.DefaultSettings.Get()
	if err != nil {
		s.oidcFailure(c)
		return
	}
	state := c.Query("state")
	cookie, cookieErr := c.Cookie(oidcCookieName)
	if cookieErr != nil || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(cookie)) != 1 {
		s.oidcFailure(c)
		return
	}
	setOIDCCookie(c, "", -1, settings)
	s.mutex.Lock()
	flow, exists := s.flows[state]
	delete(s.flows, state) // authorization responses are single use, including failures
	s.mutex.Unlock()
	if !exists || !flow.expires.After(time.Now()) || flow.revision != settings.Revision ||
		!settings.OIDC.Enabled || config.GetInstance().Authentication == "disable" || c.Query("error") != "" || c.Query("code") == "" {
		s.oidcFailure(c)
		return
	}
	provider, err := s.discoverProvider(settings)
	if err != nil {
		s.oidcFailure(c)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(c.Request.Context(), oidcHTTPClient), 20*time.Second)
	defer cancel()
	oauth := oauthConfig(settings, provider)
	tokens, err := oauth.Exchange(ctx, c.Query("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		s.oidcFailure(c)
		return
	}
	rawIDToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		s.oidcFailure(c)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: settings.OIDC.ClientID}).Verify(ctx, rawIDToken)
	if err != nil || idToken.Subject == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.nonce)) != 1 {
		s.oidcFailure(c)
		return
	}
	// go-oidc validates membership in aud; OIDC additionally identifies the
	// authorized party through azp when a token has multiple audiences.
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err = idToken.Claims(&claims); err != nil ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != settings.OIDC.ClientID) ||
		(len(idToken.Audience) > 1 && claims.AuthorizedParty == "") {
		s.oidcFailure(c)
		return
	}
	username := ""
	for _, binding := range settings.OIDC.Bindings {
		if binding.Subject == idToken.Subject {
			username = binding.Username
			break
		}
	}
	// Authenticate above before looking up an account. Unlinked realm users get
	// no device access, even when their preferred_username is "admin".
	user, err := authn.DefaultStore.Get(username)
	if err != nil || !user.Enabled {
		s.oidcFailure(c)
		return
	}
	token, err := middleware.GenerateSessionJWT(user.Username, user.TokenVersion, authn.MethodOIDC, settings.Revision, idToken.Subject, idToken.Expiry)
	if err != nil {
		s.oidcFailure(c)
		return
	}
	setSessionCookie(c, token)
	// A same-origin intermediate navigation lets browsers send the Strict
	// session cookie even when the IdP and device are on different sites.
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	c.String(http.StatusOK, `<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/"></head><body><a href="/">Continue to NanoKVM</a></body></html>`)
}

func (s *Service) oidcFailure(c *gin.Context) {
	// Never reflect provider errors or tokens into the response or logs.
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(http.StatusFound, "/#/auth/login?oidcError="+url.QueryEscape("login_failed"))
}
