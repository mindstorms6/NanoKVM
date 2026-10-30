package authn

import (
	"encoding/json"
	"fmt"
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
	if !initial.AllowsSession("", "", "", "admin", "account-id") {
		t.Fatal("legacy local session rejected by default")
	}
	initial.OIDC = OIDCSettings{Enabled: true, Issuer: "https://sso.example/realms/home", ClientID: "kvm", ClientSecret: "test-secret", RedirectURL: "https://kvm.example" + OIDCCallbackPath,
		Bindings: []OIDCBinding{{Subject: "immutable-user-id", Username: "admin", AccountID: "account-id"}}}
	saved, err := store.Save(initial, false)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision == "" || saved.AllowsSession("local", "", "", "admin", "account-id") {
		t.Fatal("old session survived revision change")
	}
	if !saved.AllowsSession(MethodOIDC, saved.Revision, "immutable-user-id", "admin", "account-id") {
		t.Fatal("linked session rejected")
	}
	if saved.AllowsSession(MethodOIDC, saved.Revision, "other-id", "admin", "account-id") || saved.AllowsSession(MethodOIDC, saved.Revision, "immutable-user-id", "other", "account-id") {
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
	if saved.AllowsSession(MethodLocal, saved.Revision, "", "admin", "account-id") {
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

func TestUsernameOnlyLinksRequireRelinkingAfterUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.json")
	settings := DefaultAuthSettings()
	settings.LocalEnabled, settings.MCPKeyEnabled = false, false
	settings.Revision = "old-revision"
	settings.OIDC = OIDCSettings{Enabled: true, Issuer: "https://sso.example", ClientID: "kvm", ClientSecret: "preserve-secret", RedirectURL: "https://kvm.example" + OIDCCallbackPath, Bindings: []OIDCBinding{{Subject: "old-subject", Username: "admin"}}}
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := NewSettingsStore(path).Get()
	if err != nil || !migrated.LocalEnabled || migrated.MCPKeyEnabled || len(migrated.OIDC.Bindings) != 0 || migrated.OIDC.ClientSecret != "preserve-secret" || migrated.Revision == settings.Revision {
		t.Fatalf("unsafe upgrade: %+v %v", migrated, err)
	}
	loaded, err := NewSettingsStore(path).Get()
	if err != nil || loaded.Revision != migrated.Revision {
		t.Fatalf("migration repeated on restart: %+v %v", loaded, err)
	}
}

func TestCorruptAccountsAndSettingsDoNotTriggerRecovery(t *testing.T) {
	for _, corrupt := range []string{"accounts", "settings"} {
		t.Run(corrupt, func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "authentication.json")
			settingsStore := NewSettingsStore(settingsPath)
			settings, err := settingsStore.Save(DefaultAuthSettings(), false)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pwd")
			if corrupt == "accounts" {
				if err = os.WriteFile(path, []byte("invalid json"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.WriteFile(settingsPath, []byte("invalid json"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err = NewStoreWithRecovery(path, settingsStore).Initialize(); err == nil {
				t.Fatal("corrupt file triggered default-account recovery")
			}
			if corrupt == "accounts" {
				after, err := settingsStore.Get()
				if err != nil || after.Revision != settings.Revision {
					t.Fatalf("corrupt account file reset settings: %+v %v", after, err)
				}
			}
		})
	}
}

func TestOlderAccountFilesRestoreFallbackWithoutReattachingLinks(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			dir := t.TempDir()
			accountPath := filepath.Join(dir, "pwd")
			accounts := NewStore(accountPath)
			if err := accounts.Initialize(); err != nil {
				t.Fatal(err)
			}
			owner, err := accounts.Get("admin")
			if err != nil {
				t.Fatal(err)
			}
			settingsStore := NewSettingsStore(filepath.Join(dir, "authentication.json"))
			settings := DefaultAuthSettings()
			settings.LocalEnabled = false
			settings.OIDC = OIDCSettings{Enabled: true, Issuer: "https://sso.example", ClientID: "kvm", RedirectURL: "https://kvm.example" + OIDCCallbackPath, Bindings: []OIDCBinding{{Subject: "owner", Username: "admin", AccountID: owner.ID}}}
			if _, err = settingsStore.Save(settings, false); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(accountPath)
			if err != nil {
				t.Fatal(err)
			}
			var db database
			if err = json.Unmarshal(data, &db); err != nil {
				t.Fatal(err)
			}
			db.Users[0].ID = ""
			data, _ = json.Marshal(db)
			if legacy {
				data, _ = json.Marshal(legacyAccount{Username: "admin", Password: owner.PasswordHash})
			}
			if err = os.WriteFile(accountPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			recovered := NewStoreWithRecovery(accountPath, settingsStore)
			user, err := recovered.Get("admin")
			if err != nil || user.ID == owner.ID || user.ID == "" {
				t.Fatalf("account did not get a new identity: %+v %v", user, err)
			}
			next, err := settingsStore.Get()
			if err != nil || !next.LocalEnabled || len(next.OIDC.Bindings) != 0 {
				t.Fatalf("older account file left OIDC-only lockout: %+v %v", next, err)
			}
			if _, ok, err := recovered.Authenticate("admin", "admin"); err != nil || !ok {
				t.Fatalf("existing password stopped working: %v", err)
			}
		})
	}
}
