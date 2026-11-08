package cmd

import (
	"errors"
	"strconv"

	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/spf13/cobra"
)

// statusCmd reports local session availability, not server-side token validity.
// Unlike auth info, its output contains no account identity or credentials.
func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Report saved-session availability without contacting Apple or disclosing account data",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := preflightKeychain(); err != nil {
				return err
			}
			out, err := dependencies.AppStore.AccountInfo()
			if err != nil && !errors.Is(err, keychain.ErrNotFound) {
				return err
			}
			dsid, parseErr := strconv.ParseUint(out.Account.DirectoryServicesID, 10, 64)
			available := err == nil && parseErr == nil && dsid != 0 && out.Account.PasswordToken != ""
			dependencies.Logger.Log().Str("schema", "ipatool-auth-status-v1").Bool("session_available", available).Bool("success", true).Send()
			return nil
		},
	}
}
