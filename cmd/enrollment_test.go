package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/log"
)

type enrollmentCommandStore struct {
	appstore.AppStore
	accountCalls, enrollmentCalls int
	fail                          error
}

func (s *enrollmentCommandStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	s.accountCalls++
	return appstore.AccountInfoOutput{Account: appstore.Account{DirectoryServicesID: "1234"}}, nil
}
func (s *enrollmentCommandStore) Enroll(input appstore.EnrollmentInput) (appstore.EnrollmentOutput, error) {
	s.enrollmentCalls++
	if input.App.ID != 42 || input.ExternalVersionID != "123" || input.Context == nil {
		return appstore.EnrollmentOutput{}, errors.New("invalid command input")
	}
	return appstore.EnrollmentOutput{App: input.App, ExternalVersionID: input.ExternalVersionID, Hardware: []byte{0, 17, 34, 51, 68, 85}, Files: map[string][]byte{"/var/db/fpsd/SC Info/SC Info.sidb": []byte("synthetic state")}, Sinfs: []appstore.Sinf{{Data: []byte("synthetic license")}}}, s.fail
}

func TestEnrollmentCommandExportsWithoutLoggingPrivateMaterial(t *testing.T) {
	previous := dependencies
	t.Cleanup(func() { dependencies = previous })
	var output bytes.Buffer
	store := &enrollmentCommandStore{}
	dependencies = Dependencies{AppStore: store, Logger: log.NewLogger(log.Args{Writer: &output})}
	dir := filepath.Join(t.TempDir(), "capture")
	cmd := enrollmentCmd()
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--app-id", "42", "--external-version-id", "123", "--output", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if store.accountCalls != 1 || store.enrollmentCalls != 1 {
		t.Fatal("unexpected account or enrollment calls")
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("synthetic")) {
		t.Fatal("private material appeared in CLI output")
	}
}

func TestEnrollmentCommandRejectsInvalidArgumentsBeforeAccountAccess(t *testing.T) {
	previous := dependencies
	t.Cleanup(func() { dependencies = previous })
	store := &enrollmentCommandStore{}
	dependencies = Dependencies{AppStore: store}
	for _, args := range [][]string{nil, {"--app-id", "-1"}, {"--app-id", "42", "--external-version-id", "0"}, {"--app-id", "42", "--external-version-id", "123"}, {"--app-id", "42", "--external-version-id", "123", "--output", t.TempDir()}} {
		cmd := enrollmentCmd()
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetContext(context.Background())
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
	if store.accountCalls != 0 || store.enrollmentCalls != 0 {
		t.Fatal("invalid CLI arguments accessed an account")
	}
}

func TestInvalidEnrollmentDoesNotInitializeProfileEvenInExecute(t *testing.T) {
	previous, previousArgs, previousOverride := dependencies, os.Args, stateDirectoryOverride
	t.Cleanup(func() { dependencies = previous; os.Args = previousArgs; stateDirectoryOverride = previousOverride })
	dependencies = Dependencies{}
	profile := filepath.Join(t.TempDir(), "unused-profile")
	os.Args = []string{"ipatool", "--state-directory", profile, "enroll", "--app-id", "42", "--external-version-id", "0"}
	if Execute() != 1 {
		t.Fatal("invalid enrollment returned success")
	}
	if dependencies.CookieJar != nil || dependencies.Keychain != nil || dependencies.AppStore != nil {
		t.Fatal("error reporting initialized account dependencies")
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatal("invalid enrollment created a profile")
	}
}

func TestCorruptProfileCookiesReturnErrorWithoutPanic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CookieJarFileName), []byte("invalid cookie JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newCookieJar(dir); err == nil {
		t.Fatal("corrupt cookie data accepted")
	}
}
