package authn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	SettingsFile     = "/etc/kvm/authentication.json"
	MethodLocal      = "local"
	MethodOIDC       = "oidc"
	OIDCCallbackPath = "/api/auth/oidc/callback"
)

// OIDC identities are explicitly linked by the immutable subject, never by a
// mutable username or email claim. Roles and permissions remain device-owned.
type OIDCBinding struct {
	Subject  string `json:"subject"`
	Username string `json:"username"`
}

type OIDCSettings struct {
	Enabled      bool          `json:"enabled"`
	DisplayName  string        `json:"displayName"`
	Issuer       string        `json:"issuer"`
	ClientID     string        `json:"clientId"`
	ClientSecret string        `json:"clientSecret,omitempty"`
	RedirectURL  string        `json:"redirectUrl"`
	Scopes       []string      `json:"scopes"`
	Bindings     []OIDCBinding `json:"bindings"`
}

type Settings struct {
	Revision      string       `json:"revision"`
	LocalEnabled  bool         `json:"localEnabled"`
	MCPKeyEnabled bool         `json:"mcpKeyEnabled"`
	OIDC          OIDCSettings `json:"oidc"`
}

type SettingsStore struct {
	path  string
	mutex sync.RWMutex
}

var DefaultSettings = NewSettingsStore(SettingsFile)

func NewSettingsStore(path string) *SettingsStore { return &SettingsStore{path: path} }

func DefaultAuthSettings() Settings {
	return Settings{LocalEnabled: true, MCPKeyEnabled: true, OIDC: OIDCSettings{
		DisplayName: "Keycloak", Scopes: []string{"openid", "profile", "email"}, Bindings: []OIDCBinding{},
	}}
}

func (s *SettingsStore) Get() (Settings, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.readLocked()
}

func (s *SettingsStore) readLocked() (Settings, error) {
	settings := DefaultAuthSettings()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if err = json.Unmarshal(data, &settings); err != nil {
		return Settings{}, err
	}
	if err = ValidateSettings(settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

// Save uses optimistic concurrency so a stale form cannot overwrite another
// administrator's changes or restore an old secret. Empty secrets preserve the
// saved value; an explicit clear is required to switch to a public client.
func (s *SettingsStore) Save(settings Settings, clearSecret bool) (Settings, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	previous, err := s.readLocked()
	if err != nil {
		return Settings{}, err
	}
	if settings.Revision != previous.Revision {
		return Settings{}, errors.New("authentication settings changed; reload before saving")
	}
	if clearSecret {
		settings.OIDC.ClientSecret = ""
	} else if settings.OIDC.ClientSecret == "" {
		settings.OIDC.ClientSecret = previous.OIDC.ClientSecret
	}
	if err = ValidateSettings(settings); err != nil {
		return Settings{}, err
	}
	var revision [32]byte
	if _, err = rand.Read(revision[:]); err != nil {
		return Settings{}, err
	}
	settings.Revision = base64.RawURLEncoding.EncodeToString(revision[:])
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return Settings{}, err
	}
	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return Settings{}, err
	}
	file, err := os.CreateTemp(dir, ".authentication-*")
	if err != nil {
		return Settings{}, err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return Settings{}, err
	}
	if closeErr != nil {
		return Settings{}, closeErr
	}
	if err = os.Rename(file.Name(), s.path); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func ValidateSettings(settings Settings) error {
	if !settings.LocalEnabled && !settings.OIDC.Enabled {
		return errors.New("at least one browser login method must remain enabled")
	}
	o := settings.OIDC
	if len(o.DisplayName) > 80 {
		return errors.New("OIDC display name is too long")
	}
	if !o.Enabled {
		return nil
	}
	if err := ValidateOIDCURL(o.Issuer, false); err != nil {
		return errors.New("issuer must be an HTTPS URL without query or fragment (HTTP is allowed on loopback only)")
	}
	if err := ValidateOIDCURL(o.RedirectURL, true); err != nil {
		return errors.New("redirect URL must be HTTPS and end with " + OIDCCallbackPath + " (HTTP is allowed on loopback only)")
	}
	if strings.TrimSpace(o.ClientID) == "" {
		return errors.New("OIDC client ID is required")
	}
	seen := map[string]bool{}
	for _, binding := range o.Bindings {
		if strings.TrimSpace(binding.Subject) == "" || len(binding.Subject) > 255 {
			return errors.New("each OIDC binding needs a subject of 1-255 characters")
		}
		if err := ValidateUsername(binding.Username); err != nil {
			return err
		}
		if seen[binding.Subject] {
			return errors.New("an OIDC subject can only be linked to one account")
		}
		seen[binding.Subject] = true
	}
	return nil
}

func ValidateOIDCURL(raw string, callback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid URL")
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return errors.New("HTTPS required")
	}
	if callback && u.Path != OIDCCallbackPath {
		return errors.New("invalid callback path")
	}
	return nil
}

// AllowsSession also validates the subject binding on each request, so deleting
// or disabling a local account continues to revoke its federated sessions.
func (s Settings) AllowsSession(method, revision, subject, username string) bool {
	if revision != s.Revision {
		return false
	}
	if method == "" || method == MethodLocal {
		return s.LocalEnabled
	}
	if method != MethodOIDC || !s.OIDC.Enabled || subject == "" {
		return false
	}
	for _, binding := range s.OIDC.Bindings {
		if binding.Subject == subject && binding.Username == username {
			return true
		}
	}
	return false
}
