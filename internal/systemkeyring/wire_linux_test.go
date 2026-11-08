//go:build linux

package systemkeyring

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// This service runs on an isolated D-Bus with synthetic values only. It checks
// actual wire signatures without touching the desktop keyring or an account.
type wireService struct {
	mu         sync.Mutex
	data       secret
	attributes map[string]string
	stored     bool
}

func (*wireService) ReadAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	if alias != "default" {
		return "/", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)
	}
	return testCollection, nil
}
func (*wireService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != "plain" {
		return dbus.MakeVariant(""), "/", dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
	}
	return dbus.MakeVariant(""), testSession, nil
}
func (*wireService) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	return dbus.MakeVariant(false), nil
}
func (s *wireService) CreateItem(properties map[string]dbus.Variant, data secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = data
	s.attributes = properties["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string)
	s.stored = true
	return testItem, "/", nil
}
func (s *wireService) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stored && s.attributes["profile"] == attributes["profile"] {
		return []dbus.ObjectPath{testItem}, nil
	}
	return []dbus.ObjectPath{}, nil
}
func (s *wireService) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data, nil
}
func (s *wireService) Delete() (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stored = false
	return "/", nil
}
func (*wireService) Close() *dbus.Error { return nil }

func TestSecretServiceWireRoundtrip(t *testing.T) {
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is required for the private-bus wire test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	process := exec.CommandContext(ctx, daemon, "--session", "--nofork", "--nopidfile", "--print-address=1")
	var diagnostics bytes.Buffer
	process.Stderr = &diagnostics
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		_ = process.Wait()
		t.Fatalf("start private D-Bus: %v (%s)", err, strings.TrimSpace(diagnostics.String()))
	}
	server, err := dbus.Connect(strings.TrimSpace(address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if _, err := server.RequestName(service, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	fixture := &wireService{}
	for _, entry := range []struct {
		path  dbus.ObjectPath
		iface string
	}{
		{root, "org.freedesktop.Secret.Service"},
		{testCollection, "org.freedesktop.DBus.Properties"},
		{testCollection, "org.freedesktop.Secret.Collection"},
		{testItem, "org.freedesktop.Secret.Item"},
		{testSession, "org.freedesktop.Secret.Session"},
	} {
		if err := server.Export(fixture, entry.path, entry.iface); err != nil {
			t.Fatal(err)
		}
	}
	client, err := dbus.Connect(strings.TrimSpace(address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	k := &Keychain{namespace: testNamespace + "/", conn: client, timeout: time.Second}
	if err := k.Preflight(); err != nil {
		t.Fatal(err)
	}
	if err := k.Set("account", []byte("synthetic wire fixture")); err != nil {
		t.Fatal(err)
	}
	other := &Keychain{namespace: "other-profile/", conn: client, timeout: time.Second}
	if _, err := other.Get("account"); err == nil {
		t.Fatal("a different profile could read the stored account")
	}
	value, err := k.Get("account")
	if err != nil || string(value) != "synthetic wire fixture" {
		t.Fatalf("wire roundtrip failed: %v", err)
	}
	if err := k.Remove("account"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get("account"); err == nil {
		t.Fatal("deleted item still exists")
	}
}
