package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

type keychainPreflight interface {
	Preflight() error
}

func preflightKeychain() error {
	check, ok := dependencies.Keychain.(keychainPreflight)
	if !ok {
		return nil
	}
	dependencies.Logger.Log().Msg("checking default system keyring before contacting Apple")
	if err := check.Preflight(); err != nil {
		return fmt.Errorf("system keyring is not ready; no login request was sent: %w", err)
	}
	dependencies.Logger.Log().Msg("default system keyring is unlocked; graphical prompting is disabled")
	return nil
}

func keyringCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keyring-check",
		Short: "Check keyring metadata without reading credentials or contacting Apple",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, ok := dependencies.Keychain.(keychainPreflight); !ok {
				return errors.New("keyring-check requires an explicit --state-directory on Linux")
			}
			return preflightKeychain()
		},
	}
}
