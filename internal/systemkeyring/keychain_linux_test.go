//go:build linux

package systemkeyring

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteness/keyring"
	"github.com/godbus/dbus/v5"
)

const (
	testNamespace  = "ipatool-test-profile"
	testCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	testSession    = dbus.ObjectPath("/org/freedesktop/secrets/session/test")
	testItem       = dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	testPrompt     = dbus.ObjectPath("/org/freedesktop/secrets/prompt/test")
)

type fakeService struct {
	collection dbus.ObjectPath
	locked     any
	data       []byte
	attributes map[string]string
	calls      []string
	prompt     dbus.ObjectPath
	dismissed  bool
	missing    bool
	duplicate  bool
	block      string
}

func newFake() *fakeService {
	return &fakeService{collection: testCollection, locked: false, prompt: "/"}
}

func (f *fakeService) invoke(ctx context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	f.calls = append(f.calls, method)
	if _, ok := ctx.Deadline(); !ok {
		return &dbus.Call{Err: errors.New("missing operation deadline")}
	}
	if method == f.block {
		<-ctx.Done()
		return &dbus.Call{Err: ctx.Err()}
	}
	var body []any
	switch method {
	case "org.freedesktop.Secret.Service.ReadAlias":
		if path != root || args[0] != "default" {
			return &dbus.Call{Err: errors.New("not resolving the default alias")}
		}
		body = []any{f.collection}
	case "org.freedesktop.DBus.Properties.Get":
		body = []any{dbus.MakeVariant(f.locked)}
	case "org.freedesktop.Secret.Service.OpenSession":
		body = []any{dbus.MakeVariant(""), testSession}
	case "org.freedesktop.Secret.Session.Close":
	case "org.freedesktop.Secret.Collection.CreateItem":
		properties := args[0].(map[string]dbus.Variant)
		f.attributes = properties["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string)
		f.data = args[1].(secret).Value
		if path != f.collection || args[2] != true {
			return &dbus.Call{Err: errors.New("wrong collection or replacement policy")}
		}
		body = []any{testItem, f.prompt}
	case "org.freedesktop.Secret.Collection.SearchItems":
		f.attributes = args[0].(map[string]string)
		items := []dbus.ObjectPath{testItem}
		if f.missing {
			items = nil
		}
		if f.duplicate {
			items = append(items, testItem)
		}
		body = []any{items}
	case "org.freedesktop.Secret.Item.GetSecret":
		body = []any{secret{testSession, []byte{}, f.data, "application/json"}}
	case "org.freedesktop.Secret.Item.Delete":
		body = []any{f.prompt}
	case "org.freedesktop.Secret.Prompt.Dismiss":
		f.dismissed = true
	default:
		return &dbus.Call{Err: errors.New("unexpected operation: " + method)}
	}
	return &dbus.Call{Body: body}
}

func (f *fakeService) keychain() *Keychain {
	return &Keychain{namespace: testNamespace + "/", invoke: f.invoke, timeout: 30 * time.Millisecond}
}

func TestPreflightUsesUnlockedDefaultWithoutSecretsOrGUI(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	f := newFake()
	// Collection names are provider-specific: do not hardcode "login".
	f.collection = "/org/freedesktop/secrets/collection/another"
	if err := f.keychain().Preflight(); err != nil {
		t.Fatal(err)
	}
	want := []string{"org.freedesktop.Secret.Service.ReadAlias", "org.freedesktop.DBus.Properties.Get"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("unexpected calls: %v", f.calls)
	}
}

func TestPreflightRejectsMissingLockedAndInvalidCollections(t *testing.T) {
	for _, test := range []struct {
		name       string
		collection dbus.ObjectPath
		locked     any
		want       string
	}{
		{"missing", "/", false, "no default system keyring"},
		{"locked", testCollection, true, "keyring is locked"},
		{"invalid collection", "not-a-path", false, "invalid default collection"},
		{"invalid lock state", testCollection, "false", "invalid lock state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFake()
			f.collection, f.locked = test.collection, test.locked
			err := f.keychain().Preflight()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, call := range f.calls {
				if call != "org.freedesktop.Secret.Service.ReadAlias" && call != "org.freedesktop.DBus.Properties.Get" {
					t.Fatalf("unexpected call: %s", call)
				}
			}
		})
	}
}

func TestAllOperationsBoundDBusWaits(t *testing.T) {
	for _, operation := range []string{"preflight", "get", "set", "remove"} {
		t.Run(operation, func(t *testing.T) {
			f := newFake()
			f.block = "org.freedesktop.Secret.Service.ReadAlias"
			k := f.keychain()
			start := time.Now()
			var err error
			switch operation {
			case "preflight":
				err = k.Preflight()
			case "get":
				_, err = k.Get("account")
			case "set":
				err = k.Set("account", []byte("synthetic"))
			case "remove":
				err = k.Remove("account")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpected error: %v", err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("operation did not respect its deadline")
			}
		})
	}
}

func TestEntriesAreNamespacedAndKeepExistingSerialization(t *testing.T) {
	f := newFake()
	k := f.keychain()
	want := []byte("synthetic-account-not-a-real-token")
	if err := k.Set("account", want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.attributes, map[string]string{"profile": testNamespace + "/account"}) {
		t.Fatalf("unsafe attributes: %v", f.attributes)
	}
	var item keyring.Item
	if err := json.Unmarshal(f.data, &item); err != nil {
		t.Fatal(err)
	}
	if item.Key != testNamespace+"/account" {
		t.Fatal("entry is not isolated")
	}
	got, err := k.Get("account")
	if err != nil || string(got) != string(want) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if err := k.Remove("account"); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1] != "org.freedesktop.Secret.Item.Delete" {
		t.Fatal("entry was not removed")
	}
}

func TestLockedCollectionIsRecheckedBeforeEveryOperation(t *testing.T) {
	f := newFake()
	k := f.keychain()
	if err := k.Preflight(); err != nil {
		t.Fatal(err)
	}
	f.locked = true
	if err := k.Set("account", []byte("synthetic")); err == nil {
		t.Fatal("write into a locked collection was attempted")
	}
	if len(f.calls) != 4 {
		t.Fatalf("unexpected calls after collection was locked: %v", f.calls)
	}
}

func TestUnexpectedPromptsAreDismissedNotShown(t *testing.T) {
	for _, operation := range []string{"set", "remove"} {
		t.Run(operation, func(t *testing.T) {
			f := newFake()
			f.prompt = testPrompt
			k := f.keychain()
			var err error
			if operation == "set" {
				err = k.Set("account", []byte("synthetic"))
			} else {
				err = k.Remove("account")
			}
			if err == nil || !strings.Contains(err.Error(), "without opening a graphical prompt") || !f.dismissed {
				t.Fatalf("prompt not handled: %v", err)
			}
		})
	}
}

func TestMissingAmbiguousAndForeignEntries(t *testing.T) {
	f := newFake()
	k := f.keychain()
	f.missing = true
	if _, err := k.Get("account"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := k.Remove("account"); err != nil {
		t.Fatal(err)
	}
	f.missing = false
	f.duplicate = true
	if _, err := k.Get("account"); err == nil {
		t.Fatal("ambiguous entries accepted")
	}
	f.duplicate = false
	f.data, _ = json.Marshal(keyring.Item{Key: "account", Data: []byte("foreign")})
	if _, err := k.Get("account"); err == nil {
		t.Fatal("foreign entry accepted")
	}
	f.data = []byte("invalid secret JSON")
	if _, err := k.Get("account"); err == nil || strings.Contains(err.Error(), "invalid secret JSON") {
		t.Fatal("malformed secret accepted or exposed")
	}
}

func TestLiveDefaultSystemKeyringPreflight(t *testing.T) {
	if os.Getenv("IPATOOL_KEYRING_LIVE_TEST") != "1" {
		t.Skip("opt-in metadata-only check of the user's default keyring")
	}
	k := New(testNamespace)
	if err := k.Preflight(); err != nil {
		t.Fatal(err)
	}
	if k.conn != nil {
		t.Cleanup(func() { _ = k.conn.Close() })
	}
	t.Log("default system keyring is unlocked; no credentials read, written, or sent")
}
