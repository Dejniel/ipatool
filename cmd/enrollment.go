package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

func enrollmentCmd() *cobra.Command {
	var appID int64
	var version, output, destination string
	cmd := &cobra.Command{
		Use: "enroll", Short: "Export private FairPlay state for offline IPA analysis",
		Long: "Authorize an already licensed app and import its keybag in the same native session.\nExports private hardware, SC Info state and licenses; does not purchase, decrypt or download an IPA.",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return err
			}
			if appID <= 0 {
				return errors.New("a positive --app-id is required")
			}
			if value, err := strconv.ParseUint(version, 10, 64); err != nil || value == 0 {
				return errors.New("a positive --external-version-id is required")
			}
			if output == "" {
				return errors.New("--output is required")
			}
			var err error
			destination, err = filepath.Abs(output)
			if err != nil {
				return err
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				return errors.New("enrollment output must not exist")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := preflightKeychain(); err != nil {
				return err
			}
			store := dependencies.AppStore
			account, err := store.AccountInfo()
			if err != nil {
				return err
			}
			material, err := store.Enroll(appstore.EnrollmentInput{
				Context: cmd.Context(), Account: account.Account, App: appstore.App{ID: appID}, ExternalVersionID: version,
				Progress: func(stage string) { dependencies.Logger.Log().Msg(stage) },
			})
			if err != nil {
				return err
			}
			defer func() {
				clear(material.Hardware)
				for _, data := range material.Files {
					clear(data)
				}
				for _, sinf := range material.Sinfs {
					clear(sinf.Data)
				}
			}()
			if _, err := appstore.WriteEnrollment(cmd.Context(), destination, material); err != nil {
				return err
			}
			dependencies.Logger.Log().Str("output", destination).Bool("success", true).Send()
			return nil
		},
	}
	cmd.Flags().Int64Var(&appID, "app-id", 0, "Numeric ID of an app already licensed to this account")
	cmd.Flags().StringVar(&version, "external-version-id", "", "Exact external version identifier")
	cmd.Flags().StringVarP(&output, "output", "o", "", "New private export directory (must not exist)")
	return cmd
}
