//go:build linux

package systemkeyring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/byteness/keyring"
	"github.com/godbus/dbus/v5"
)

const (
	service          = "org.freedesktop.secrets"
	root             = dbus.ObjectPath("/org/freedesktop/secrets")
	operationTimeout = 5 * time.Second
)

// Keychain uses the existing default Secret Service collection. It never
// creates collections, unlocks them, or invokes a provider's graphical prompt.
type Keychain struct {
	namespace string
	mu        sync.Mutex
	conn      *dbus.Conn
	invoke    func(context.Context, dbus.ObjectPath, string, ...any) *dbus.Call
	timeout   time.Duration
}

type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func New(namespace string) *Keychain {
	return &Keychain{namespace: namespace + "/", timeout: operationTimeout}
}

func (k *Keychain) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	if k.invoke != nil {
		return k.invoke(ctx, path, method, args...)
	}
	return k.conn.Object(service, path).CallWithContext(ctx, method, 0, args...)
}

func (k *Keychain) ready(ctx context.Context) (dbus.ObjectPath, error) {
	if k.conn == nil && k.invoke == nil {
		conn, err := dbus.SessionBusPrivateNoAutoStartup()
		if err != nil {
			return "", fmt.Errorf("connect to the user D-Bus: %w", err)
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		err = conn.Auth(nil)
		if err == nil {
			err = conn.Hello()
		}
		stop()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			_ = conn.Close()
			return "", fmt.Errorf("authenticate to the user D-Bus: %w", err)
		}
		k.conn = conn
	}

	var collection dbus.ObjectPath
	err := k.call(ctx, root, "org.freedesktop.Secret.Service.ReadAlias", "default").Store(&collection)
	if err != nil {
		return "", fmt.Errorf("find default system keyring: %w", err)
	}
	if collection == "/" {
		return "", errors.New("no default system keyring exists; configure one before logging in; no graphical prompt was opened")
	}
	if !collection.IsValid() {
		return "", errors.New("Secret Service returned an invalid default collection")
	}

	var locked dbus.Variant
	err = k.call(ctx, collection, "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Locked").Store(&locked)
	if err != nil {
		return "", fmt.Errorf("check default system keyring: %w", err)
	}
	value, ok := locked.Value().(bool)
	if !ok {
		return "", errors.New("Secret Service returned an invalid lock state")
	}
	if value {
		return "", errors.New("default system keyring is locked; unlock it using GNOME Keyring or its login integration before retrying; no graphical prompt was opened")
	}
	return collection, nil
}

// Preflight reads only collection metadata, before any Apple credentials are
// requested or sent. The same checks are repeated for every storage operation.
func (k *Keychain) Preflight() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	_, err := k.ready(ctx)
	return err
}

func (k *Keychain) attributes(key string) map[string]string {
	return map[string]string{"profile": k.namespace + key}
}

func (k *Keychain) session(ctx context.Context) (dbus.ObjectPath, error) {
	var output dbus.Variant
	var path dbus.ObjectPath
	err := k.call(ctx, root, "org.freedesktop.Secret.Service.OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &path)
	if err != nil {
		return "", fmt.Errorf("open Secret Service session: %w", err)
	}
	if !path.IsValid() || path == "/" {
		return "", errors.New("Secret Service returned an invalid session")
	}
	return path, nil
}

func (k *Keychain) closeSession(path dbus.ObjectPath) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = k.call(ctx, path, "org.freedesktop.Secret.Session.Close").Err
}

func (k *Keychain) find(ctx context.Context, collection dbus.ObjectPath, key string) (dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	err := k.call(ctx, collection, "org.freedesktop.Secret.Collection.SearchItems", k.attributes(key)).Store(&paths)
	if err != nil {
		return "", fmt.Errorf("find keyring entry: %w", err)
	}
	if len(paths) == 0 {
		return "", keyring.ErrKeyNotFound
	}
	if len(paths) != 1 || !paths[0].IsValid() || paths[0] == "/" {
		return "", errors.New("Secret Service returned ambiguous or invalid keyring entries")
	}
	return paths[0], nil
}

func (k *Keychain) rejectPrompt(ctx context.Context, prompt dbus.ObjectPath) error {
	if prompt == "/" {
		return nil
	}
	if prompt.IsValid() {
		_ = k.call(ctx, prompt, "org.freedesktop.Secret.Prompt.Dismiss").Err
	}
	return errors.New("system keyring requires user interaction; operation cancelled without opening a graphical prompt; unlock the keyring before retrying")
}

func (k *Keychain) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	collection, err := k.ready(ctx)
	if err != nil {
		return nil, err
	}
	path, err := k.find(ctx, collection, key)
	if err != nil {
		return nil, err
	}
	session, err := k.session(ctx)
	if err != nil {
		return nil, err
	}
	defer k.closeSession(session)
	var data secret
	if err := k.call(ctx, path, "org.freedesktop.Secret.Item.GetSecret", session).Store(&data); err != nil {
		return nil, fmt.Errorf("read keyring entry: %w", err)
	}
	if data.Session != session || len(data.Parameters) != 0 {
		return nil, errors.New("Secret Service returned an invalid plain-session secret")
	}
	var item keyring.Item
	if err := json.Unmarshal(data.Value, &item); err != nil || item.Key != k.namespace+key {
		return nil, errors.New("invalid keyring entry")
	}
	return item.Data, nil
}

func (k *Keychain) Set(key string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	collection, err := k.ready(ctx)
	if err != nil {
		return err
	}
	session, err := k.session(ctx)
	if err != nil {
		return err
	}
	defer k.closeSession(session)
	encoded, err := json.Marshal(keyring.Item{Key: k.namespace + key, Data: data, Label: "ipatool"})
	if err != nil {
		return fmt.Errorf("encode keyring entry: %w", err)
	}
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(k.namespace + " " + key),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(k.attributes(key)),
	}
	var item, prompt dbus.ObjectPath
	err = k.call(ctx, collection, "org.freedesktop.Secret.Collection.CreateItem", properties, secret{session, []byte{}, encoded, "application/json"}, true).Store(&item, &prompt)
	if err != nil {
		return fmt.Errorf("save keyring entry: %w", err)
	}
	if err := k.rejectPrompt(ctx, prompt); err != nil {
		return err
	}
	if !item.IsValid() || item == "/" {
		return errors.New("Secret Service did not return a saved item")
	}
	return nil
}

func (k *Keychain) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	collection, err := k.ready(ctx)
	if err != nil {
		return err
	}
	path, err := k.find(ctx, collection, key)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var prompt dbus.ObjectPath
	if err := k.call(ctx, path, "org.freedesktop.Secret.Item.Delete").Store(&prompt); err != nil {
		return fmt.Errorf("remove keyring entry: %w", err)
	}
	return k.rejectPrompt(ctx, prompt)
}
