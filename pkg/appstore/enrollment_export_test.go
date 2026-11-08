package appstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func syntheticEnrollment() EnrollmentOutput {
	return EnrollmentOutput{Hardware: []byte{0, 17, 34, 51, 68, 85}, App: App{ID: 42, BundleID: "example.test"}, ExternalVersionID: "123", Files: map[string][]byte{"/var/db/fpsd/SC Info/SC Info.sidb": []byte("synthetic SIDB")}, Sinfs: []Sinf{{ID: 0, Data: []byte("synthetic license")}}}
}

func TestEnrollmentExportIsPrivateHashedAndNeverReplacesState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	manifest, err := WriteEnrollment(context.Background(), dir, syntheticEnrollment())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != EnrollmentSchema || !manifest.NativeImportComplete {
		t.Fatal("incomplete manifest")
	}
	for _, file := range append(append([]EnrollmentFile{manifest.Hardware}, manifest.State...), manifest.Licenses[0].File) {
		path := filepath.Join(dir, filepath.FromSlash(file.Path))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(path)
		sum := sha256.Sum256(data)
		if info.Mode().Perm() != 0600 || len(data) != file.Bytes || file.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("file integrity or permissions lost")
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("export directory is not private")
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"password", "token", "account", "kbsync", "keybag", "decrypted"} {
		if _, ok := document[key]; ok {
			t.Fatalf("unexpected sensitive/unsupported field %s", key)
		}
	}
	if _, err := WriteEnrollment(context.Background(), dir, syntheticEnrollment()); err == nil {
		t.Fatal("existing export was overwritten")
	}
}

func TestEnrollmentExportRejectsEscapingPathsBeforeCreatingOutput(t *testing.T) {
	for _, name := range []string{"../../escape", "/etc/passwd", "/var/db/fpsd/SC Info/../SC Info.sidb"} {
		out := syntheticEnrollment()
		out.Files[name] = []byte("synthetic")
		dir := filepath.Join(t.TempDir(), "export")
		if _, err := WriteEnrollment(context.Background(), dir, out); err == nil {
			t.Fatal("invalid path accepted")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("invalid material changed the filesystem")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteEnrollment(canceled, filepath.Join(t.TempDir(), "export"), syntheticEnrollment()); err == nil {
		t.Fatal("canceled export proceeded")
	}
}
