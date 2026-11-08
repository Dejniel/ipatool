//go:build linux

package cmd

import (
	"github.com/majd/ipatool/v2/internal/systemkeyring"
	"github.com/majd/ipatool/v2/pkg/keychain"
)

func newKeychain(stateDirectory string, interactive bool) keychain.Keychain {
	if stateDirectoryOverride != "" {
		return systemkeyring.New(keychainNamespace(stateDirectory))
	}
	return newDefaultKeychain(stateDirectory, interactive)
}
