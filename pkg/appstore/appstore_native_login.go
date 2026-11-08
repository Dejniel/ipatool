package appstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const storeAMDKeychainKey = "store-amd-v1"

func (t *appstore) nativeLogin(input LoginInput) (LoginOutput, error) {
	if _, err := normalizeAuthCode(input.AuthCode); err != nil {
		return LoginOutput{}, err
	}
	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()
	if err := t.loadStoreAMDState(); err != nil {
		return LoginOutput{}, err
	}
	ctx := context.Background()
	macAddress, err := t.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get Store machine identity: %w", err)
	}
	guid, hardwareID, err := machineIdentity(macAddress)
	if err != nil {
		return LoginOutput{}, err
	}
	bag, err := t.bag(guid)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get Store authentication bag: %w", err)
	}
	if len(t.storeAMDState) == 0 {
		if t.amdProvisioner == nil {
			return LoginOutput{}, errors.New("Store AMD provisioner is not configured")
		}
		state, err := t.amdProvisioner(ctx, t.authHTTP, nil, hardwareID)
		if err != nil {
			return LoginOutput{}, fmt.Errorf("provision Store AMD identity: %w", err)
		}
		if err := t.keychain.Set(storeAMDKeychainKey, state); err != nil {
			return LoginOutput{}, fmt.Errorf("save Store AMD provisioning: %w", err)
		}
		t.storeAMDState = state
	}
	proof, err := t.refreshStoreAMDProof(ctx, bag.AuthEndpoint, hardwareID)
	if err != nil {
		return LoginOutput{}, err
	}
	t.authenticationHeaders = make(http.Header)
	for name, value := range proof {
		t.authenticationHeaders.Set(name, value)
	}
	defer func() { t.authenticationHeaders = nil }()

	return t.legacyLogin(input)
}
