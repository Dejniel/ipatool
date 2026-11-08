package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/log"
)

func TestAuthStatusDoesNotDiscloseAccountOrLogIn(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			previous := dependencies
			t.Cleanup(func() { dependencies = previous })
			store := &fakeDownloadAppStore{account: appstore.Account{Email: "private@example.invalid", PasswordToken: "private-token", DirectoryServicesID: "1234", Password: "private-password"}}
			if missing {
				store.accountInfoError = fmt.Errorf("read account: %w", keychain.ErrNotFound)
			}
			var output bytes.Buffer
			dependencies = Dependencies{AppStore: store, Logger: log.NewLogger(log.Args{Writer: &output})}
			cmd := statusCmd()
			cmd.SetContext(context.Background())
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if len(store.loginInputs) != 0 || len(store.downloadInputs) != 0 {
				t.Fatal("status attempted an account operation")
			}
			if bytes.Contains(output.Bytes(), []byte("private")) {
				t.Fatal("status disclosed account data")
			}
			want := fmt.Sprintf(`"session_available":%v`, !missing)
			if !bytes.Contains(output.Bytes(), []byte(want)) {
				t.Fatal("wrong status contract")
			}
		})
	}
}

func TestNoReauthReturnsExpiryWithoutLogin(t *testing.T) {
	previous := dependencies
	t.Cleanup(func() { dependencies = previous })
	store := &fakeDownloadAppStore{downloadErrors: []error{appstore.ErrPasswordTokenExpired}}
	dependencies.Logger = log.NewLogger(log.Args{})
	cmd := downloadCmdWithAppStore(func() appstore.AppStore { return store })
	cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
	cmd.SetArgs([]string{"--app-id", "42", "--no-reauth"})
	if err := cmd.Execute(); !errors.Is(err, appstore.ErrPasswordTokenExpired) {
		t.Fatal("expiry was not returned")
	}
	if len(store.loginInputs) != 0 || len(store.downloadInputs) != 1 {
		t.Fatal("expiry retried authentication or download")
	}
}

func TestCommandErrorCodesUnwrapTypedFailures(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{appstore.ErrPasswordTokenExpired, "session-expired"}, {appstore.ErrAuthCodeRequired, "auth-code-required"},
		{appstore.ErrLicenseRequired, "license-required"}, {keychain.ErrNotFound, "session-missing"}, {errors.New("other"), "command-failed"},
	} {
		if got := commandErrorCode(fmt.Errorf("wrapped: %w", test.err)); got != test.code {
			t.Fatalf("code %q, want %q", got, test.code)
		}
	}
}
