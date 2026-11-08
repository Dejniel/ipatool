package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/majd/ipatool/v2/pkg/log"
)

type preflightTestKeychain struct {
	err   error
	calls int
}

func (k *preflightTestKeychain) Preflight() error { k.calls++; return k.err }
func (k *preflightTestKeychain) Get(string) ([]byte, error) {
	return nil, errors.New("unexpected credential read")
}
func (k *preflightTestKeychain) Set(string, []byte) error {
	return errors.New("unexpected credential write")
}
func (k *preflightTestKeychain) Remove(string) error {
	return errors.New("unexpected credential removal")
}

func TestKeyringFailureStopsBeforeCredentialsAndApple(t *testing.T) {
	previous := dependencies
	t.Cleanup(func() { dependencies = previous })
	k := &preflightTestKeychain{err: errors.New("locked")}
	store := &fakeLoginAppStore{}
	dependencies = Dependencies{Keychain: k, AppStore: store, Logger: log.NewLogger(log.Args{})}
	cmd := loginCmd()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil || !errors.Is(err, k.err) {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.calls != 1 || store.loginCalls != 0 {
		t.Fatal("login did not stop at keyring preflight")
	}
}

func TestKeyringCheckNeverLogsIn(t *testing.T) {
	previous := dependencies
	t.Cleanup(func() { dependencies = previous })
	k := &preflightTestKeychain{}
	store := &fakeLoginAppStore{}
	dependencies = Dependencies{Keychain: k, AppStore: store, Logger: log.NewLogger(log.Args{})}
	cmd := keyringCheckCmd()
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if k.calls != 1 || store.loginCalls != 0 {
		t.Fatal("check used something other than metadata preflight")
	}
}
