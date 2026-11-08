//go:build !linux

package cmd

import "github.com/majd/ipatool/v2/pkg/keychain"

func newKeychain(stateDirectory string, interactive bool) keychain.Keychain {
	return newDefaultKeychain(stateDirectory, interactive)
}
