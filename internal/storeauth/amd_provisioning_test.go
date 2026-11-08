package storeauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"howett.net/plist"
)

type amdTestTransport func(*http.Request) (*http.Response, error)

func (send amdTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return send(request)
}

type rejectedAMDSession struct{ closed bool }

func (*rejectedAMDSession) StartProvisioning(uint64, []byte) ([]byte, uint32, error) {
	return nil, 0, errors.New("rejected challenge reached native provisioning")
}

func (*rejectedAMDSession) EndProvisioning(uint32, []byte, []byte) error {
	return errors.New("rejected challenge reached native completion")
}

func (*rejectedAMDSession) State() ([]byte, error) {
	return nil, errors.New("rejected challenge created state")
}

func (session *rejectedAMDSession) Close() error {
	session.closed = true
	return nil
}

func TestStoreAMDProvisioningTrustsOnlyAppleHTTPS(t *testing.T) {
	for _, endpoint := range []string{
		"http://gsa.apple.com/start", "https://apple.com.example.test/start",
		"https://example.test/start", "https://user@gsa.apple.com/start",
		"https://gsa.apple.com:8443/start", "https://gsa.apple.com/start#secret",
		"https://gsa.apple.com/%73tart",
	} {
		if appleProvisioningURL(endpoint) {
			t.Fatalf("untrusted endpoint accepted: %s", endpoint)
		}
	}
	if !appleProvisioningURL(storeProvisioningBag) || !appleProvisioningURL(storeProvisioningLookup) {
		t.Fatal("pinned Apple endpoints rejected")
	}
}

func TestStoreAMDProvisioningRejectsInvalidInputsBeforeNetwork(t *testing.T) {
	client := &http.Client{Transport: amdTestTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid provisioning reached the network")
		return nil, errors.New("unexpected network")
	})}
	encoded, err := json.Marshal(anisetteState{Identifier: make([]byte, 16), Provisioning: []byte("already provisioned")})
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		ctx      context.Context
		client   *http.Client
		state    []byte
		hardware []byte
	}{
		{nil, client, nil, make([]byte, 6)},
		{context.Background(), nil, nil, make([]byte, 6)},
		{canceled, client, nil, make([]byte, 6)},
		{context.Background(), client, nil, nil},
		{context.Background(), client, encoded, make([]byte, 6)},
		{context.Background(), client, []byte("invalid state"), make([]byte, 6)},
	} {
		if _, err := ProvisionStoreAMD(input.ctx, input.client, input.state, input.hardware); err == nil {
			t.Fatal("invalid provisioning input accepted")
		}
	}
}

func TestStoreAMDProvisioningDoesNotSendAccountCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(storeProvisioningLookup)
	jar.SetCookies(origin, []*http.Cookie{{Name: "account", Value: "synthetic secret", Domain: ".apple.com"}})
	requests := 0
	client := &http.Client{Jar: jar, Transport: amdTestTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
			t.Fatal("account credentials entered anonymous provisioning")
		}
		var response map[string]any
		switch request.URL.String() {
		case storeProvisioningBag:
			response = map[string]any{"amd-finish-provisioning": "https://auth.itunes.apple.com/finish"}
		case storeProvisioningLookup:
			response = map[string]any{"urls": map[string]any{"midStartProvisioning": "https://gsa.apple.com/start"}}
		case "https://gsa.apple.com/start":
			if request.Method != http.MethodPost {
				t.Fatal("provisioning start did not use POST")
			}
			response = map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": 42}}}
		default:
			t.Fatal("unexpected provisioning destination")
		}
		body, _ := json.Marshal(response)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	session := &rejectedAMDSession{}
	if _, err := provisionStoreAMD(context.Background(), client, nil, make([]byte, 6), func(context.Context, []byte) (storeAMDSession, error) {
		if requests != 0 {
			t.Fatal("requested provisioning before native assets were ready")
		}
		return session, nil
	}); err == nil || !strings.Contains(err.Error(), "was rejected") {
		t.Fatal("rejected start advanced into native provisioning")
	}
	if requests != 3 || client.Jar != jar || len(jar.Cookies(origin)) != 1 || !session.closed {
		t.Fatal("provisioning changed the original client or its account cookies")
	}
}

func TestStoreAMDProvisioningDoesNotFollowRedirects(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: amdTestTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://example.test/collect"}},
			Body: io.NopCloser(strings.NewReader("")), Request: request,
		}, nil
	})}
	if _, err := provisionStoreAMD(context.Background(), client, nil, make([]byte, 6), func(context.Context, []byte) (storeAMDSession, error) {
		return &rejectedAMDSession{}, nil
	}); err == nil || requests != 1 {
		t.Fatal("provisioning followed a redirect or ignored its status")
	}
}

type completedAMDSession struct {
	t     *testing.T
	steps []string
}

func (s *completedAMDSession) StartProvisioning(dsid uint64, challenge []byte) ([]byte, uint32, error) {
	if dsid != ^uint64(0) || string(challenge) != "synthetic SPIM" {
		s.t.Fatal("native start lost the Store DSID or challenge")
	}
	s.steps = append(s.steps, "start")
	return []byte("synthetic CPIM"), 17, nil
}

func (s *completedAMDSession) EndProvisioning(session uint32, setting, transport []byte) error {
	if session != 17 || string(setting) != "synthetic setting" || !bytes.Equal(transport, bytes.Repeat([]byte{3}, 16)) {
		s.t.Fatal("native completion lost the session or response")
	}
	s.steps = append(s.steps, "finish")
	return nil
}

func (s *completedAMDSession) State() ([]byte, error) {
	s.steps = append(s.steps, "state")
	return []byte("synthetic adi.pb"), nil
}

func (s *completedAMDSession) Close() error {
	s.steps = append(s.steps, "close")
	return nil
}

// This verifies HTTP/state wiring with fixtures, not Apple's cryptography.
// The separately opted-in runtime tests execute the actual native routines.
func TestStoreAMDProvisioningKeepsOneNativeSession(t *testing.T) {
	session := &completedAMDSession{t: t}
	var identifier []byte
	var deviceID string
	requests := 0
	client := &http.Client{Transport: amdTestTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		current := request.Header.Get("X-Mme-Device-Id")
		if current == "" || (deviceID != "" && current != deviceID) {
			t.Fatal("provisioning changed identity between requests")
		}
		deviceID = current
		var response map[string]any
		switch request.URL.String() {
		case storeProvisioningBag:
			response = map[string]any{"amd-finish-provisioning": "https://auth.itunes.apple.com/finish"}
		case storeProvisioningLookup:
			response = map[string]any{"urls": map[string]any{"midStartProvisioning": "https://gsa.apple.com/start"}}
		case "https://gsa.apple.com/start":
			response = map[string]any{"Response": map[string]any{
				"Status": map[string]any{"ec": 0}, "spim": base64.StdEncoding.EncodeToString([]byte("synthetic SPIM")),
			}}
		case "https://auth.itunes.apple.com/finish":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if _, err := plist.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["guid"] != "001122AABBCC" || payload["clientData"] != base64.StdEncoding.EncodeToString([]byte("synthetic CPIM")) {
				t.Fatal("finish request lost the device GUID or native client data")
			}
			response = map[string]any{
				"settingInfo":  base64.StdEncoding.EncodeToString([]byte("synthetic setting")),
				"transportKey": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)),
			}
		default:
			t.Fatal("unexpected endpoint")
		}
		body, err := plist.Marshal(response, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	state, err := provisionStoreAMD(context.Background(), client, nil, []byte{0, 17, 34, 170, 187, 204}, func(_ context.Context, id []byte) (storeAMDSession, error) {
		identifier = bytes.Clone(id)
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAnisetteState(state)
	if err != nil || !bytes.Equal(decoded.Identifier, identifier) || string(decoded.Provisioning) != "synthetic adi.pb" {
		t.Fatal("native identity/state was not persisted")
	}
	if requests != 4 || strings.Join(session.steps, ",") != "start,finish,state,close" {
		t.Fatalf("unexpected native session lifetime: %v", session.steps)
	}
}
