package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

const (
	principalContextKey = "principal"
	tokenContextKey     = "token"
	CookieName          = "nano-kvm-token"
	sessionRecheckDelay = 5 * time.Second
)

type Principal struct {
	Username    string
	Role        authn.Role
	Permissions []authn.Permission
	AuthMethod  string
	OIDCSubject string
}

// Has reports whether the principal effectively holds the permission.
// Administrators always do.
func (p Principal) Has(permission authn.Permission) bool {
	if p.Role == authn.RoleAdmin {
		return true
	}
	return authn.Has(p.Permissions, permission)
}

type Token struct {
	Username     string `json:"username"`
	TokenVersion uint64 `json:"tokenVersion"`
	AuthMethod   string `json:"authMethod,omitempty"`
	AuthRevision string `json:"authRevision,omitempty"`
	OIDCSubject  string `json:"oidcSubject,omitempty"`
	jwt.RegisteredClaims
}

func CheckToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, token, ok := authenticate(c)
		if !ok {
			abortUnauthorized(c)
			return
		}

		c.Set(principalContextKey, principal)
		c.Set(tokenContextKey, token)
		if token == nil || token.ExpiresAt == nil {
			c.Next()
			return
		}

		requestContext, cancel := context.WithCancel(c.Request.Context())
		sessionHandle := newSessionHandle()
		requestContext = WithSessionHandle(requestContext, sessionHandle)
		c.Request = c.Request.WithContext(requestContext)
		channel := SessionChannelForPath(c.Request.URL.Path)
		unregister := activeSessions.register(
			principal.Username,
			cancel,
			sessionHandle,
			channel,
		)
		// The principal was resolved before this session could be found by a
		// revocation, so a grant edit landing in between would miss it. Now that
		// it is registered, any later edit drops it; re-reading the account picks
		// up any earlier one. Only the long-lived channels are dropped by a grant
		// edit, so a short request keeps the principal it was authorized with.
		if channel != "" {
			user, err := validateSession(token)
			if err != nil {
				unregister()
				cancel()
				abortUnauthorized(c)
				return
			}
			principal.Role = user.Role
			principal.Permissions = authn.EffectivePermissions(user)
			c.Set(principalContextKey, principal)
		}

		timer := time.AfterFunc(time.Until(token.ExpiresAt.Time), cancel)
		go watchTokenState(requestContext, cancel, token, sessionRecheckDelay)
		defer func() {
			timer.Stop()
			unregister()
			cancel()
		}()

		c.Next()
	}
}

func watchTokenState(ctx context.Context, cancel context.CancelFunc, token *Token, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := validateSession(token); err != nil {
				cancel()
				return
			}
		}
	}
}

func validateSession(token *Token) (*authn.User, error) {
	settings, err := authn.CurrentSettings()
	if err != nil {
		return nil, err
	}
	user, err := authn.DefaultStore.ValidateToken(token.Username, token.TokenVersion)
	if err != nil {
		return nil, err
	}
	if !settings.AllowsSession(token.AuthMethod, token.AuthRevision, token.OIDCSubject, token.Username, user.ID) {
		return nil, errors.New("login method disabled or authentication settings changed")
	}
	return user, nil
}

func RequireRole(roles ...authn.Role) gin.HandlerFunc {
	allowed := make(map[authn.Role]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(c *gin.Context) {
		principal, ok := CurrentPrincipal(c)
		if !ok {
			abortUnauthorized(c)
			return
		}
		if _, ok = allowed[principal.Role]; !ok {
			abortForbidden(c)
			return
		}
		c.Next()
	}
}

// RequirePermission allows the request when the principal holds at least one
// of the listed permissions. Administrators implicitly hold every permission.
func RequirePermission(permissions ...authn.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := CurrentPrincipal(c)
		if !ok {
			abortUnauthorized(c)
			return
		}
		allowed := false
		for _, permission := range permissions {
			if principal.Has(permission) {
				allowed = true
				break
			}
		}
		if !allowed {
			abortForbidden(c)
			return
		}
		c.Next()
	}
}

func CurrentPrincipal(c *gin.Context) (Principal, bool) {
	value, exists := c.Get(principalContextKey)
	if !exists {
		return Principal{}, false
	}
	principal, ok := value.(Principal)
	return principal, ok
}

func CurrentToken(c *gin.Context) *Token {
	value, _ := c.Get(tokenContextKey)
	token, _ := value.(*Token)
	return token
}

func CheckLoopbackInternalToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowByLoopbackInternalToken(c.Request) {
			c.Next()
			return
		}
		abortUnauthorized(c)
	}
}

func CheckTokenOrLoopbackInternalToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowByLoopbackInternalToken(c.Request) {
			c.Next()
			return
		}

		principal, token, ok := authenticate(c)
		if !ok {
			abortUnauthorized(c)
			return
		}
		c.Set(principalContextKey, principal)
		c.Set(tokenContextKey, token)
		c.Next()
	}
}

func authenticate(c *gin.Context) (Principal, *Token, bool) {
	conf := config.GetInstance()
	if conf.Authentication == "disable" {
		return Principal{Username: "admin", Role: authn.RoleAdmin, Permissions: authn.PermissionIDs()}, nil, true
	}

	cookie, err := c.Cookie(CookieName)
	if err != nil {
		return Principal{}, nil, false
	}
	token, err := ParseJWT(cookie)
	if err != nil {
		return Principal{}, nil, false
	}
	user, err := validateSession(token)
	if err != nil {
		log.Debugf("validate session for %q: %s", token.Username, err)
		return Principal{}, nil, false
	}
	return Principal{
		Username:    user.Username,
		Role:        user.Role,
		Permissions: authn.EffectivePermissions(user),
		AuthMethod:  token.AuthMethod,
		OIDCSubject: token.OIDCSubject,
	}, token, true
}

func abortUnauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, "unauthorized")
	c.Abort()
}

func abortForbidden(c *gin.Context) {
	c.JSON(http.StatusForbidden, "forbidden")
	c.Abort()
}

func GenerateJWT(username string, tokenVersion uint64) (string, error) {
	settings, err := authn.CurrentSettings()
	if err != nil {
		return "", err
	}
	return GenerateSessionJWT(username, tokenVersion, authn.MethodLocal, settings.Revision, "", time.Time{})
}

// OIDC sessions never outlive the verified ID token. Provider access and refresh
// tokens are not kept or exposed to the browser.
func GenerateSessionJWT(username string, tokenVersion uint64, method, revision, subject string, expires time.Time) (string, error) {
	conf := config.GetInstance()
	now := time.Now()
	expireDuration := time.Duration(conf.JWT.RefreshTokenDuration) * time.Second
	if expires.IsZero() || expires.After(now.Add(expireDuration)) {
		expires = now.Add(expireDuration)
	}
	claims := Token{
		Username:     username,
		TokenVersion: tokenVersion,
		AuthMethod:   method,
		AuthRevision: revision,
		OIDCSubject:  subject,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(conf.JWT.SecretKey))
}

func ParseJWT(jwtToken string) (*Token, error) {
	conf := config.GetInstance()
	parsed, err := jwt.ParseWithClaims(
		jwtToken,
		&Token{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(conf.JWT.SecretKey), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		log.Debugf("parse jwt error: %s", err)
		return nil, err
	}
	claims, ok := parsed.Claims.(*Token)
	if !ok || !parsed.Valid || claims.Username == "" || claims.Subject != claims.Username || claims.TokenVersion == 0 {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
