package cmd

import (
	"context"
	"errors"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

var version = "dev"

type contextKey string

const interactiveKey contextKey = "interactive"

func rootCmd() *cobra.Command {
	var (
		verbose        bool
		nonInteractive bool
		format         OutputFormat
	)

	cmd := &cobra.Command{
		Use:           "ipatool",
		Short:         "A cli tool for interacting with Apple's ipa files",
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.WithValue(cmd.Context(), interactiveKey, !nonInteractive)
			cmd.SetContext(ctx)
			return initWithCommand(cmd)
		},
	}

	cmd.PersistentFlags().VarP(
		enumflag.New(&format, "format", map[OutputFormat][]string{
			OutputFormatText: {"text"},
			OutputFormatJSON: {"json"},
		}, enumflag.EnumCaseSensitive), "format", "", "sets output format for command; can be 'text', 'json'")
	cmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enables verbose logs")
	cmd.PersistentFlags().BoolVarP(&nonInteractive, "non-interactive", "", false, "run in non-interactive session")
	cmd.PersistentFlags().StringVar(&keychainPassphrase, "keychain-passphrase", "", "passphrase for unlocking keychain")
	cmd.PersistentFlags().StringVar(&stateDirectoryOverride, "state-directory", "", "absolute private profile directory; never migrates existing sessions")

	cmd.AddCommand(authCmd())
	cmd.AddCommand(downloadCmd())
	cmd.AddCommand(enrollmentCmd())
	cmd.AddCommand(listPurchasesCmd())
	cmd.AddCommand(purchaseCmd())
	cmd.AddCommand(searchCmd())
	cmd.AddCommand(ListVersionsCmd())
	cmd.AddCommand(getVersionMetadataCmd())
	cmd.AddCommand(mcpCmd())

	return cmd
}

// Execute runs the program and returns the appropriate exit status code.
func Execute() int {
	cmd := rootCmd()
	err := cmd.Execute()

	if err != nil {
		if dependencies.Logger == nil {
			format, parseErr := OutputFormatFromString(cmd.Flag("format").Value.String())
			if parseErr != nil {
				format = OutputFormatText
			}
			dependencies.Logger = newLogger(format, cmd.Flag("verbose").Value.String() == "true")
		}

		var appstoreErr *appstore.Error
		if errors.As(err, &appstoreErr) {
			dependencies.Logger.Verbose().Stack().
				Err(err).
				Interface("metadata", appstoreErr.Metadata).
				Send()
		} else {
			dependencies.Logger.Verbose().Stack().Err(err).Send()
		}

		dependencies.Logger.Error().
			Err(err).
			Bool("success", false).
			Send()

		return 1
	}

	return 0
}
