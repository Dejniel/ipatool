package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitProfileDoesNotInspectOrMigrateLegacyState(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, ConfigDirectoryName)
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(legacy, "untouched")
	if err := os.WriteFile(sentinel, []byte("original session"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "isolated")
	// A nil OS proves the explicit branch never consults legacy/XDG storage.
	got, err := resolveStateDirectory(nil, home, profile)
	if err != nil || got != profile {
		t.Fatalf("resolve explicit profile: %q, %v", got, err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "original session" {
		t.Fatalf("legacy state was changed: %v", err)
	}
	info, err := os.Stat(profile)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("profile is not private: %v", err)
	}
}

func TestExplicitProfileRejectsUnsafePaths(t *testing.T) {
	base := t.TempDir()
	public := filepath.Join(base, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(base, "link")
	if err := os.Symlink(public, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", file, public, symlink} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := resolveStateDirectory(nil, "", path); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
	info, _ := os.Stat(public)
	if info.Mode().Perm() != 0755 {
		t.Fatal("permissions of an existing directory were silently changed")
	}
}

func TestProfileNamespaceUsesCanonicalDirectory(t *testing.T) {
	previous := stateDirectoryOverride
	t.Cleanup(func() { stateDirectoryOverride = previous })
	stateDirectoryOverride = "explicit"
	base := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(base, alias); err != nil {
		t.Fatal(err)
	}
	a, err := resolveStateDirectory(nil, "", filepath.Join(base, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := resolveStateDirectory(nil, "", filepath.Join(alias, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b || keychainNamespace(a) != keychainNamespace(b) {
		t.Fatal("parent symlinks created multiple identities for one profile")
	}
	if keychainNamespace(a) == keychainNamespace(filepath.Join(base, "another")) {
		t.Fatal("separate profiles share keychain entries")
	}
	stateDirectoryOverride = ""
	if keychainNamespace(a) != KeychainServiceName {
		t.Fatal("default storage namespace changed")
	}
}
