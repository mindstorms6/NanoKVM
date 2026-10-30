package authn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsPersistenceAndSessionRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.json")
	store := NewSettingsStore(path)
	initial, err := store.Get()
	if err != nil || !initial.LocalEnabled || !initial.MCPKeyEnabled || initial.OIDC.Enabled {
		t.Fatalf("defaults: %+v %v", initial, err)
	}
	if !initial.AllowsSession("", "", "", "admin") {
		t.Fatal("legacy local session rejected by default")
	}
	initial.OIDC = OIDCSettings{Enabled: true, Issuer: "https://sso.example/realms/home", ClientID: "kvm", ClientSecret: "test-secret", RedirectURL: "https://kvm.example" + OIDCCallbackPath,
		Bindings: []OIDCBinding{{Subject: "immutable-user-id", Username: "admin"}}}
	saved, err := store.Save(initial, false)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision == "" || saved.AllowsSession("local", "", "", "admin") {
		t.Fatal("old session survived revision change")
	}
	if !saved.AllowsSession(MethodOIDC, saved.Revision, "immutable-user-id", "admin") {
		t.Fatal("linked session rejected")
	}
	if saved.AllowsSession(MethodOIDC, saved.Revision, "other-id", "admin") || saved.AllowsSession(MethodOIDC, saved.Revision, "immutable-user-id", "other") {
		t.Fatal("unlinked session accepted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("settings permissions: %v %v", info, err)
	}
	if _, err = store.Save(initial, false); err == nil {
		t.Fatal("stale update accepted")
	}
	saved.OIDC.ClientSecret = ""
	saved, err = store.Save(saved, false)
	if err != nil || saved.OIDC.ClientSecret != "test-secret" {
		t.Fatalf("secret not preserved: %v", err)
	}
	saved, err = store.Save(saved, true)
	if err != nil || saved.OIDC.ClientSecret != "" {
		t.Fatalf("secret not cleared: %v", err)
	}
	saved.LocalEnabled = false
	saved.MCPKeyEnabled = false
	saved, err = store.Save(saved, false)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AllowsSession(MethodLocal, saved.Revision, "", "admin") {
		t.Fatal("disabled password method accepted")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "test-secret") {
		t.Fatal("removed secret persisted")
	}
	loaded, err := NewSettingsStore(path).Get()
	if err != nil || loaded.LocalEnabled || loaded.MCPKeyEnabled || !loaded.OIDC.Enabled {
		t.Fatalf("restart changed settings: %+v %v", loaded, err)
	}
	if err = os.WriteFile(path, []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Get(); err == nil {
		t.Fatal("corrupt configuration did not fail closed")
	}
}

func TestSettingsRejectUnsafeURLsAndNoLogin(t *testing.T) {
	settings := DefaultAuthSettings()
	settings.LocalEnabled = false
	if err := ValidateSettings(settings); err == nil {
		t.Fatal("all browser methods disabled")
	}
	for _, raw := range []string{"http://sso.example/realms/home", "https://user:pass@sso.example", "https://sso.example#fragment", "https://sso.example?query=1", "javascript:alert(1)"} {
		if ValidateOIDCURL(raw, false) == nil {
			t.Errorf("unsafe issuer accepted: %s", raw)
		}
	}
	if err := ValidateOIDCURL("http://127.0.0.1:8888"+OIDCCallbackPath, true); err != nil {
		t.Fatal(err)
	}
	if ValidateOIDCURL("https://kvm.example/wrong-callback", true) == nil {
		t.Fatal("wrong callback accepted")
	}
}
