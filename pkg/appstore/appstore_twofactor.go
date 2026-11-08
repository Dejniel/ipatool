package appstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/majd/ipatool/v2/internal/grandslam"
	"github.com/majd/ipatool/v2/internal/storeauth"
	"github.com/majd/ipatool/v2/pkg/keychain"
)

type TwoFactorMethod = grandslam.Method
type TwoFactorPrompts = grandslam.Prompts

const twoFactorStateKey = "authkit-anisette-v1"

func (t *appstore) selectTwoFactor(input LoginInput) (string, error) {
	if input.TwoFactor.Select == nil || input.TwoFactor.Code == nil {
		return "", errors.New("selectable 2FA requires selection and code prompts")
	}
	if t.authHTTP == nil {
		return "", errors.New("selectable 2FA HTTP client is not configured")
	}
	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()
	state, err := t.keychain.Get(twoFactorStateKey)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return "", fmt.Errorf("read 2FA machine state: %w", err)
	}
	ctx := context.Background()
	// AuthKit has its own provisioning identity; never overwrite Store AMD.
	headers, updated, err := storeauth.AnisetteHeaders(ctx, t.authHTTP, state)
	if err != nil {
		return "", fmt.Errorf("prepare selectable 2FA: %w", err)
	}
	if err := t.keychain.Set(twoFactorStateKey, updated); err != nil {
		return "", fmt.Errorf("save 2FA machine state: %w", err)
	}
	prompts := *input.TwoFactor
	readCode := prompts.Code
	prompts.Code = func() (string, error) {
		code, err := readCode()
		if err != nil {
			return "", err
		}
		return normalizeAuthCode(code)
	}
	return grandslam.New(t.authHTTP, headers).Authenticate(ctx, input.Email, input.Password, prompts)
}
