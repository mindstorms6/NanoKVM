package mcpservice

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"NanoKVM-Server/authn"
	"NanoKVM-Server/service/controlmode"
	"github.com/gin-gonic/gin"
)

func TestAPIKeyAuthenticationCanBeDisabledIndependently(t *testing.T) {
	useTestConfig(t)
	control := controlmode.NewManager(filepath.Join(t.TempDir(), "mode"), controlmode.ModeMCP)
	const key = "nag_mcp_test"
	if _, err := updateConfig(func(Config) (Config, error) { return Config{APIKey: key}, nil }); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/api/mcp", APIKeyMiddleware(control), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := func() int {
		r := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		router.ServeHTTP(r, req)
		return r.Code
	}
	if request() != http.StatusNoContent {
		t.Fatal("valid key rejected")
	}
	settings, err := authn.DefaultSettings.Get()
	if err != nil {
		t.Fatal(err)
	}
	settings.MCPKeyEnabled = false
	settings, err = authn.DefaultSettings.Save(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	if request() != http.StatusForbidden {
		t.Fatal("disabled key method accepted")
	}
	settings.MCPKeyEnabled = true
	if _, err = authn.DefaultSettings.Save(settings, false); err != nil {
		t.Fatal(err)
	}
	if request() != http.StatusNoContent {
		t.Fatal("re-enabled key method rejected")
	}
}
