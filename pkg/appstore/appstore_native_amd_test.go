package appstore

import (
	"bytes"
	"context"
	"errors"
	gohttp "net/http"
	"strings"
	"testing"

	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"go.uber.org/mock/gomock"
)

func TestNativeAMDLoginUsesOnlyStoreProof(t *testing.T) {
	for _, saved := range []bool{false, true} {
		name := "fresh"
		if saved {
			name = "saved"
		}
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			keys := keychain.NewMockKeychain(ctrl)
			host := machine.NewMockMachine(ctrl)
			bagClient := http.NewMockClient[bagResult](ctrl)
			loginClient := http.NewMockClient[loginResult](ctrl)
			state := []byte("synthetic provisioned state")
			if saved {
				keys.EXPECT().Get(storeAMDKeychainKey).Return(state, nil)
			} else {
				keys.EXPECT().Get(storeAMDKeychainKey).Return(nil, keychain.ErrNotFound)
				keys.EXPECT().Set(storeAMDKeychainKey, state).Return(nil)
			}
			keys.EXPECT().Set(storeAMDKeychainKey, []byte("synthetic next state")).Return(nil)
			host.EXPECT().MacAddress().Return("00:11:22:33:44:55", nil).Times(2)
			bagClient.EXPECT().Send(gomock.Any()).Return(http.Result[bagResult]{StatusCode: 200, Data: validBagResult()}, nil).Times(2)
			stop := errors.New("stop at synthetic authentication transport")
			loginClient.EXPECT().Send(gomock.Any()).DoAndReturn(func(request http.Request) (http.Result[loginResult], error) {
				amd, mid := "", ""
				for name, value := range request.Headers {
					switch {
					case strings.EqualFold(name, "X-Apple-AMD"):
						amd = value
					case strings.EqualFold(name, "X-Apple-AMD-M"):
						mid = value
					case strings.EqualFold(name, "X-Apple-I-MD"), strings.EqualFold(name, "X-Apple-I-MD-M"):
						t.Fatal("AuthKit proof substituted for Store AMD")
					}
				}
				if amd != "synthetic AMD" || mid != "synthetic MID" {
					t.Fatal("native Store proofs did not reach the authentication request")
				}
				return http.Result[loginResult]{}, stop
			})
			provisions := 0
			client := &appstore{
				keychain: keys, machine: host, bagClient: bagClient, loginClient: loginClient,
				amdProvisioner: func(_ context.Context, _ *gohttp.Client, previous, hardware []byte) ([]byte, error) {
					provisions++
					if len(previous) != 0 || !bytes.Equal(hardware, []byte{0, 17, 34, 51, 68, 85}) {
						t.Fatal("provisioning received the wrong profile or device binding")
					}
					return state, nil
				},
				amdHeaderGenerator: func(_ context.Context, previous []byte, endpoint string, hardware []byte) (map[string]string, []byte, error) {
					if !bytes.Equal(previous, state) || endpoint != validSAPConfig().AuthEndpoint || len(hardware) != 6 {
						t.Fatal("proof generation lost its persisted state or endpoint binding")
					}
					return map[string]string{"X-Apple-AMD": "synthetic AMD", "X-Apple-AMD-M": "synthetic MID"}, []byte("synthetic next state"), nil
				},
				actionSignerFactory: func(SAPConfig, []byte) (ActionSigner, error) { return &stubActionSigner{}, nil },
			}
			_, err := client.nativeLogin(LoginInput{Email: "synthetic@example.test", Password: "synthetic"})
			if !errors.Is(err, stop) || client.authenticationHeaders != nil || !bytes.Equal(client.storeAMDState, []byte("synthetic next state")) {
				t.Fatal("native login did not preserve the transport error, clear proofs or persist state")
			}
			want := 1
			if saved {
				want = 0
			}
			if provisions != want {
				t.Fatal("saved AMD identity was reprovisioned")
			}
		})
	}
}

func TestNativeAMDLoginStopsOnLockedKeychain(t *testing.T) {
	ctrl := gomock.NewController(t)
	keys := keychain.NewMockKeychain(ctrl)
	locked := errors.New("synthetic locked keychain")
	keys.EXPECT().Get(storeAMDKeychainKey).Return(nil, locked)
	client := &appstore{keychain: keys}
	if _, err := client.nativeLogin(LoginInput{}); !errors.Is(err, locked) {
		t.Fatal("locked keychain was treated as an absent identity")
	}
}

func TestNativeAMDLoginRejectsInvalidCodeBeforeStateAccess(t *testing.T) {
	client := &appstore{}
	if _, err := client.nativeLogin(LoginInput{AuthCode: "bad"}); err == nil || !strings.Contains(err.Error(), "six digits") {
		t.Fatal("invalid 2FA input reached native authentication preparation")
	}
}
