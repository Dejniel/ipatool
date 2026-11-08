//go:build linux

package appstore

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/internal/systemkeyring"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"go.uber.org/mock/gomock"
	"howett.net/plist"
)

type enrollmentMemoryKeys map[string][]byte

func (k enrollmentMemoryKeys) Get(name string) ([]byte, error) {
	data, ok := k[name]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return bytes.Clone(data), nil
}
func (k enrollmentMemoryKeys) Set(name string, data []byte) error {
	k[name] = bytes.Clone(data)
	return nil
}
func (k enrollmentMemoryKeys) Remove(name string) error { delete(k, name); return nil }

// Opt-in integration with a read-only credential source. Cookies and all
// updated AMD state are isolated copies. No login, purchase or IPA download.
func TestLiveEnrollmentAuthorization(t *testing.T) {
	configPath := os.Getenv("IPATOOL_ENROLLMENT_LIVE_CONFIG")
	if configPath == "" {
		t.Skip("explicit private live enrollment configuration required")
	}
	read := func(path string) []byte {
		t.Helper()
		info, err := os.Lstat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
			t.Fatal("invalid private live-test input")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read private live-test input")
		}
		return data
	}
	var config struct {
		KeychainNamespace, Cookies, AMDState, Hardware, IPA, Output string
		AppID                                                       int64
	}
	data := read(configPath)
	err := json.Unmarshal(data, &config)
	clear(data)
	if err != nil || config.KeychainNamespace == "" || config.AppID <= 0 {
		t.Fatal("invalid live enrollment configuration")
	}
	if !filepath.IsAbs(config.Output) {
		t.Fatal("absolute private export directory required")
	}
	if _, err := os.Lstat(config.Output); !os.IsNotExist(err) {
		t.Fatal("live export already exists")
	}
	keys := systemkeyring.New(config.KeychainNamespace)
	if err := keys.Preflight(); err != nil {
		t.Fatal("source keyring is unavailable; no login attempted")
	}
	encoded, err := keys.Get("account")
	if err != nil {
		t.Fatal("source account is unavailable; no login attempted")
	}
	defer clear(encoded)
	var account Account
	if err := json.Unmarshal(encoded, &account); err != nil {
		t.Fatal("invalid saved account")
	}
	hardware := read(config.Hardware)
	defer clear(hardware)
	if len(hardware) != 6 {
		t.Fatal("invalid hardware identity")
	}
	amd := read(config.AMDState)
	defer clear(amd)
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	cookies := read(config.Cookies)
	cookiePath := filepath.Join(private, "cookies")
	err = os.WriteFile(cookiePath, cookies, 0600)
	clear(cookies)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(&cookiejar.Options{Filename: cookiePath})
	if err != nil {
		t.Fatal("invalid private cookie copy")
	}
	archive, err := zip.OpenReader(config.IPA)
	if err != nil {
		t.Fatal("cannot inspect private IPA metadata")
	}
	defer archive.Close()
	version := ""
	for _, member := range archive.File {
		if member.Name != "iTunesMetadata.plist" {
			continue
		}
		reader, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := io.ReadAll(io.LimitReader(reader, 1<<20))
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		_, err = plist.Unmarshal(metadata, &fields)
		clear(metadata)
		if err != nil {
			t.Fatal("invalid IPA metadata")
		}
		version = fmt.Sprint(fields["softwareVersionExternalIdentifier"])
	}
	if n, err := strconv.ParseUint(version, 10, 64); err != nil || n == 0 {
		t.Fatal("IPA has no external version identifier")
	}
	ctrl := gomock.NewController(t)
	host := machine.NewMockMachine(ctrl)
	host.EXPECT().MacAddress().Return(net.HardwareAddr(hardware).String(), nil).AnyTimes()
	memory := enrollmentMemoryKeys{storeAMDKeychainKey: bytes.Clone(amd)}
	defer func() {
		for _, data := range memory {
			clear(data)
		}
	}()
	store := NewAppStore(Args{Keychain: memory, CookieJar: jar, Machine: host, OperatingSystem: operatingsystem.New()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := store.Enroll(EnrollmentInput{Context: ctx, Account: account, App: App{ID: config.AppID}, ExternalVersionID: version, Progress: func(stage string) { t.Log(stage) }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		clear(out.Hardware)
		for _, data := range out.Files {
			clear(data)
		}
		for _, license := range out.Sinfs {
			clear(license.Data)
		}
	}()
	manifest, err := WriteEnrollment(ctx, config.Output, out)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.NativeImportComplete || len(manifest.State) == 0 {
		t.Fatal("native enrollment is incomplete")
	}
	t.Log("fresh native enrollment exported; source account, cookies and AMD profile were not modified")
}
