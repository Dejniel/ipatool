package storeauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/sap/machine"
)

// This opt-in check downloads public pinned assets and opens guest runtimes.
// It does not provision an identity, read a keychain or authenticate an account.
func TestLiveModernADIRuntime(t *testing.T) {
	if os.Getenv("IPATOOL_ADI_RUNTIME_TEST") != "1" {
		t.Skip("explicit native ADI runtime check required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	t.Log("loading hash-pinned public Apple assets")
	bundle, err := assets.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		t.Fatal(err)
	}
	t.Log("opening the modern ADI client and guest services with a fresh identifier")
	adi, err := machine.OpenModernADI(ctx, bundle, identifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := adi.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("native ADI runtime initialized and closed; no provisioning or account requests")
}

func TestLiveStoreAMDProvisioning(t *testing.T) {
	if os.Getenv("IPATOOL_AMD_PROVISION_TEST") != "1" {
		t.Skip("explicit account-free Store AMD provisioning required")
	}
	root := os.Getenv("IPATOOL_AMD_TEST_DIR")
	info, err := os.Lstat(root)
	if !filepath.IsAbs(root) || err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("an existing private absolute result directory is required")
	}
	dir, err := os.MkdirTemp(root, "provision-")
	if err != nil {
		t.Fatal(err)
	}
	hardware := make([]byte, 6)
	if _, err := rand.Read(hardware); err != nil {
		t.Fatal(err)
	}
	writeLiveAMDFile(t, dir, "hardware.bin", hardware)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	t.Log("provisioning a fresh Store AMD identity; no Apple account or keychain")
	state, err := ProvisionStoreAMD(ctx, NewHTTPClient(nil), nil, hardware)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveAMDFile(t, dir, "state.json", state)
	t.Log("native provisioning finished; reopening persisted state for AppleMediaServices")
	checkLiveAMDState(t, dir)
}

func TestLiveStoreAMDHeaders(t *testing.T) {
	dir := os.Getenv("IPATOOL_AMD_CHECK_DIR")
	if dir == "" {
		t.Skip("explicit private Store AMD state check required")
	}
	checkLiveAMDState(t, dir)
}

func checkLiveAMDState(t *testing.T, dir string) {
	t.Helper()
	state := readLiveAMDFile(t, dir, "state.json")
	hardware := readLiveAMDFile(t, dir, "hardware.bin")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	headers, nextState, err := StoreAMDHeaders(ctx, state, "https://auth.itunes.apple.com/auth/v1/authenticate", hardware)
	if err != nil {
		t.Fatal(err)
	}
	validateLiveAMDHeaders(t, headers)
	encoded, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveAMDFile(t, dir, "headers.json", encoded)
	writeLiveAMDFile(t, dir, "next-state.json", nextState)
	summary, _ := json.Marshal(map[string]any{
		"schema": "ipatool-native-amd-check-v1", "native_provisioning_completed": true,
		"headers_generated": true, "amd_bytes": 24, "machine_id_bytes": 60,
		"login_performed": false, "keyring_access": false, "helper_process_used": false,
	})
	writeLiveAMDFile(t, dir, "report.json", summary)
	t.Logf("native Store AMD headers generated; private result=%s", filepath.Base(dir))
}

func TestLiveStoreAMDReopen(t *testing.T) {
	dir := os.Getenv("IPATOOL_AMD_REOPEN_DIR")
	if dir == "" {
		t.Skip("explicit private persisted Store AMD state required")
	}
	state := readLiveAMDFile(t, dir, "next-state.json")
	hardware := readLiveAMDFile(t, dir, "hardware.bin")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	headers, _, err := StoreAMDHeaders(ctx, state, "https://auth.itunes.apple.com/auth/v1/authenticate", hardware)
	if err != nil {
		t.Fatal(err)
	}
	validateLiveAMDHeaders(t, headers)
	previous := readLiveAMDFile(t, dir, "headers.json")
	var saved map[string]string
	if err := json.Unmarshal(previous, &saved); err != nil || saved["X-Apple-AMD-M"] != headers["X-Apple-AMD-M"] {
		t.Fatal("persisted Store identity changed")
	}
	t.Log("persisted native AMD state reopened in a new process without provisioning or a helper")
}

func validateLiveAMDHeaders(t *testing.T, headers map[string]string) {
	t.Helper()
	for name, size := range map[string]int{"X-Apple-AMD": 24, "X-Apple-AMD-M": 60} {
		data, err := base64.StdEncoding.DecodeString(headers[name])
		if err != nil || len(data) != size {
			t.Fatalf("unexpected native header format for %s: decoded bytes=%d, expected=%d", name, len(data), size)
		}
	}
}

func writeLiveAMDFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cannot write private AMD test result")
	}
}

func readLiveAMDFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	info, err := os.Lstat(dir)
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private absolute AMD result directory required")
	}
	path := filepath.Join(dir, name)
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > anisetteLimit*2 {
		t.Fatal("invalid private AMD test file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
