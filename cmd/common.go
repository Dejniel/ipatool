package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/byteness/keyring"
	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/log"
	"github.com/majd/ipatool/v2/pkg/util"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var dependencies = Dependencies{}
var keychainPassphrase string
var stateDirectoryOverride string

type Dependencies struct {
	Logger    log.Logger
	OS        operatingsystem.OperatingSystem
	Machine   machine.Machine
	CookieJar http.CookieJar
	Keychain  keychain.Keychain
	AppStore  appstore.AppStore
}

// newLogger returns a new logger instance.
func newLogger(format OutputFormat, verbose bool) log.Logger {
	var writer io.Writer

	switch format {
	case OutputFormatJSON:
		writer = zerolog.SyncWriter(os.Stdout)
	case OutputFormatText:
		writer = log.NewWriter()
	}

	return log.NewLogger(log.Args{
		Verbose: verbose,
		Writer:  writer,
	},
	)
}

// newCookieJar returns a new cookie jar instance.
func newCookieJar(stateDirectory string) (http.CookieJar, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(stateDirectory, CookieJarFileName),
	})
	if err != nil {
		return nil, fmt.Errorf("open profile cookies: %w", err)
	}
	return jar, nil
}

func newDefaultKeychain(stateDirectory string, interactive bool) keychain.Keychain {
	serviceName := keychainNamespace(stateDirectory)
	ring := util.Must(openKeyring(keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
			keyring.FileBackend,
		},
		ServiceName:              serviceName,
		KeychainTrustApplication: true,
		FileDir:                  stateDirectory,
		FilePasswordFunc: func(s string) (string, error) {
			if keychainPassphrase == "" && !interactive {
				return "", errors.New("keychain passphrase is required when not running in interactive mode; use the \"--keychain-passphrase\" flag")
			}

			if keychainPassphrase != "" {
				return keychainPassphrase, nil
			}

			path := strings.Split(s, " unlock ")[1]
			password, err := readPrompt(fmt.Sprintf("enter passphrase to unlock %s (this is separate from your Apple ID password): ", path), true)
			if err != nil {
				return "", fmt.Errorf("failed to read password: %w", err)
			}

			return password, nil
		},
	}))

	return keychain.New(keychain.Args{
		Keyring: ring,
		Label:   serviceName,
	})
}

// initWithCommand initializes the dependencies of the command.
func initWithCommand(cmd *cobra.Command) error {
	verbose := cmd.Flag("verbose").Value.String() == "true"
	interactive, _ := cmd.Context().Value(interactiveKey).(bool)
	format := util.Must(OutputFormatFromString(cmd.Flag("format").Value.String()))

	dependencies.Logger = newLogger(format, verbose)
	if cmd.Name() == "mcp" {
		dependencies.Logger = log.NewLogger(log.Args{Verbose: verbose, Writer: zerolog.SyncWriter(os.Stderr)})
	}

	dependencies.OS = operatingsystem.New()
	dependencies.Machine = machine.New(machine.Args{OS: dependencies.OS})
	stateDirectory, err := resolveStateDirectory(dependencies.OS, dependencies.Machine.HomeDirectory(), stateDirectoryOverride)
	if err != nil {
		return err
	}
	dependencies.CookieJar, err = newCookieJar(stateDirectory)
	if err != nil {
		return err
	}
	dependencies.Keychain = newKeychain(stateDirectory, interactive)
	dependencies.AppStore = appstore.NewAppStore(appstore.Args{
		CookieJar:       dependencies.CookieJar,
		OperatingSystem: dependencies.OS,
		Keychain:        dependencies.Keychain,
		Machine:         dependencies.Machine,
	})
	return nil
}
