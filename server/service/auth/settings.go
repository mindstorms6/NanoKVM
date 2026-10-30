package auth

import (
	"net/http"
	"reflect"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/proto"

	"github.com/gin-gonic/gin"
)

func (s *Service) LoginMethods(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	settings, err := authn.DefaultSettings.Get()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": -1, "msg": "authentication unavailable"})
		return
	}
	var rsp proto.Response
	rsp.OkRspWithData(c, gin.H{
		"localEnabled":           settings.LocalEnabled,
		"oidcEnabled":            settings.OIDC.Enabled,
		"oidcDisplayName":        settings.OIDC.DisplayName,
		"authenticationDisabled": config.GetInstance().Authentication == "disable",
	})
}

func redactedSettings(settings authn.Settings) gin.H {
	configured := settings.OIDC.ClientSecret != ""
	settings.OIDC.ClientSecret = ""
	return gin.H{"settings": settings, "clientSecretConfigured": configured}
}

func (s *Service) GetSettings(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var rsp proto.Response
	settings, err := authn.DefaultSettings.Get()
	if err != nil {
		rsp.ErrRsp(c, -1, "failed to load authentication settings")
		return
	}
	rsp.OkRspWithData(c, redactedSettings(settings))
}

func (s *Service) SetSettings(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var rsp proto.Response
	if err := http.NewCrossOriginProtection().Check(c.Request); err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if config.GetInstance().Authentication == "disable" {
		rsp.ErrRsp(c, -1, "enable authentication in server.yaml before configuring login methods")
		return
	}
	var req struct {
		authn.Settings
		ClearClientSecret bool `json:"clearClientSecret"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	if err := c.ShouldBindJSON(&req); err != nil {
		rsp.ErrRsp(c, -1, "invalid authentication settings")
		return
	}
	previous, err := authn.DefaultSettings.Get()
	if err != nil {
		rsp.ErrRsp(c, -1, "failed to load authentication settings")
		return
	}
	next := req.Settings
	if req.ClearClientSecret {
		next.OIDC.ClientSecret = ""
	} else if next.OIDC.ClientSecret == "" {
		next.OIDC.ClientSecret = previous.OIDC.ClientSecret
	}
	if err = authn.ValidateSettings(next); err != nil {
		rsp.ErrRsp(c, -1, err.Error())
		return
	}
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok {
		rsp.ErrRsp(c, -1, "invalid session")
		return
	}
	if next.OIDC.Enabled {
		hasAdmin := false
		for _, binding := range next.OIDC.Bindings {
			user, getErr := authn.DefaultStore.Get(binding.Username)
			if getErr != nil {
				rsp.ErrRsp(c, -1, "OIDC bindings must name existing local accounts")
				return
			}
			if user.Enabled && user.Role == authn.RoleAdmin {
				hasAdmin = true
			}
		}
		if !next.LocalEnabled && !hasAdmin {
			rsp.ErrRsp(c, -1, "OIDC-only login requires a linked, enabled administrator")
			return
		}
	}
	// Prove the replacement login works before turning off the fallback. Do not
	// change the provider and remove the fallback in the same save.
	sameOIDC := reflect.DeepEqual(previous.OIDC, next.OIDC)
	if !next.LocalEnabled && (principal.AuthMethod != authn.MethodOIDC || !sameOIDC ||
		!next.AllowsSession(authn.MethodOIDC, next.Revision, principal.OIDCSubject, principal.Username)) {
		rsp.ErrRsp(c, -1, "save OIDC settings and sign in as an OIDC administrator before disabling password login")
		return
	}
	if next.OIDC.Enabled {
		if _, err = s.discoverProvider(next); err != nil {
			rsp.ErrRsp(c, -1, "OIDC discovery failed; check issuer, TLS trust and connectivity")
			return
		}
	}
	saved, err := authn.DefaultSettings.Save(req.Settings, req.ClearClientSecret)
	if err != nil {
		rsp.ErrRsp(c, -1, err.Error())
		return
	}
	// The new revision invalidates every previous session and pending flow.
	if users, listErr := authn.DefaultStore.List(); listErr == nil {
		for _, user := range users {
			middleware.RevokeUserSessions(user.Username)
		}
	}
	method := principal.AuthMethod
	if method == "" {
		method = authn.MethodLocal
	}
	if saved.AllowsSession(method, saved.Revision, principal.OIDCSubject, principal.Username) && (method != authn.MethodOIDC || sameOIDC) {
		user, getErr := authn.DefaultStore.Get(principal.Username)
		oldToken := middleware.CurrentToken(c)
		if getErr == nil && oldToken != nil && oldToken.ExpiresAt != nil {
			token, tokenErr := middleware.GenerateSessionJWT(user.Username, user.TokenVersion, method, saved.Revision, principal.OIDCSubject, oldToken.ExpiresAt.Time)
			if tokenErr == nil {
				setSessionCookie(c, token)
			} else {
				clearSessionCookie(c)
			}
		} else {
			clearSessionCookie(c)
		}
	} else {
		clearSessionCookie(c)
	}
	rsp.OkRspWithData(c, redactedSettings(saved))
}
