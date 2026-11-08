package cmd

import (
	"errors"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/keychain"
)

func commandErrorCode(err error) string {
	switch {
	case errors.Is(err, appstore.ErrAuthCodeRequired):
		return "auth-code-required"
	case errors.Is(err, appstore.ErrPasswordTokenExpired):
		return "session-expired"
	case errors.Is(err, appstore.ErrLicenseRequired):
		return "license-required"
	case errors.Is(err, keychain.ErrNotFound):
		return "session-missing"
	default:
		return "command-failed"
	}
}
