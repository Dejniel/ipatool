package appstore

import (
	"context"
	"errors"
	"fmt"
	gohttp "net/http"
	"net/url"
	"strings"

	"github.com/majd/ipatool/v2/pkg/keychain"
)

type storeAMDProvisioner func(context.Context, *gohttp.Client, []byte, []byte) ([]byte, error)
type storeAMDHeaderGenerator func(context.Context, []byte, string, []byte) (map[string]string, []byte, error)

func (t *appstore) storeAMDProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if len(hardwareID) != 6 {
		return nil, errors.New("store AMD proof requires a six-byte device GUID")
	}

	if !isStoreAMDCommerceURL(endpoint) {
		return nil, errors.New("store AMD proof endpoint is not allowlisted")
	}

	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()

	if err := t.loadStoreAMDState(); err != nil {
		return nil, err
	}
	return t.refreshStoreAMDProof(ctx, endpoint, hardwareID)
}

func (t *appstore) refreshStoreAMDProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	if t.amdHeaderGenerator == nil {
		return nil, errors.New("Store AMD header generator is not configured")
	}
	proof, state, err := t.amdHeaderGenerator(ctx, t.storeAMDState, endpoint, hardwareID)
	if err != nil {
		return nil, fmt.Errorf("generate Store AMD proof: %w", err)
	}

	if t.keychain == nil {
		return nil, errors.New("keychain is not configured")
	}

	if err = t.keychain.Set(storeAMDKeychainKey, state); err != nil {
		return nil, fmt.Errorf("save Store AMD state: %w", err)
	}

	t.storeAMDState = state

	return proof, nil
}

func (t *appstore) loadStoreAMDState() error {
	if t.keychain == nil {
		return errors.New("keychain is not configured")
	}
	if len(t.storeAMDState) != 0 {
		return nil
	}
	state, err := t.keychain.Get(storeAMDKeychainKey)
	if errors.Is(err, keychain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Store AMD state: %w", err)
	}
	t.storeAMDState = state
	return nil
}

func isStoreAMDCommerceURL(endpoint string) bool {
	if strings.Contains(endpoint, "#") {
		return false
	}

	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Opaque != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || parsed.ForceQuery || len(query) != 1 {
		return false
	}

	values, ok := query["guid"]
	if !ok || len(values) != 1 || values[0] == "" {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	switch host {
	case downloadDispatchDomain:
		switch parsed.Path {
		case entDownloadPath, redownloadProductPath, updateProductPath:
			return true
		}
	default:
		if !isStoreBuyHost(host) {
			return false
		}

		switch parsed.Path {
		case PrivateAppStoreAPIPathDownload:
			return true
		}
	}

	return false
}

func isStoreBuyHost(host string) bool {
	if host == PrivateAppStoreAPIDomain {
		return true
	}

	const suffix = "-" + PrivateAppStoreAPIDomain

	pod := strings.TrimSuffix(host, suffix)
	if pod == host || len(pod) < 2 || pod[0] != 'p' {
		return false
	}

	for _, digit := range pod[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}

	return true
}
