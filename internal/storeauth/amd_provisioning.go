package storeauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/sap/machine"
	"howett.net/plist"
)

const (
	storeProvisioningLookup = "https://gsa.apple.com/grandslam/GsService2/lookup"
	storeProvisioningBag    = "https://init.itunes.apple.com/bag.xml?ix=6"
)

type storeAMDSession interface {
	StartProvisioning(uint64, []byte) ([]byte, uint32, error)
	EndProvisioning(uint32, []byte, []byte) error
	State() ([]byte, error)
	Close() error
}

type storeAMDSessionOpener func(context.Context, []byte) (storeAMDSession, error)

// ProvisionStoreAMD creates a Store-specific ADI state without an Apple account.
// Native commerce/adid code owns the provisioning session throughout the HTTP
// exchange. This provisions AMD, not an application FairPlay license.
func ProvisionStoreAMD(ctx context.Context, client *http.Client, encoded, hardwareID []byte) ([]byte, error) {
	return provisionStoreAMD(ctx, client, encoded, hardwareID, func(ctx context.Context, identifier []byte) (storeAMDSession, error) {
		bundle, err := assets.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("load Store AMD provisioning assets: %w", err)
		}
		return machine.OpenModernADI(ctx, bundle, identifier, nil)
	})
}

func provisionStoreAMD(ctx context.Context, client *http.Client, encoded, hardwareID []byte, open storeAMDSessionOpener) ([]byte, error) {
	if ctx == nil || client == nil {
		return nil, errors.New("Store AMD provisioning requires a context and HTTP client")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(hardwareID) != 6 {
		return nil, errors.New("Store AMD provisioning requires a six-byte device GUID")
	}
	state, err := decodeAnisetteState(encoded)
	if err != nil {
		return nil, err
	}
	if len(state.Provisioning) != 0 {
		return nil, errors.New("Store AMD provisioning will not replace an existing profile")
	}
	// Prepare/download native assets before requesting a short-lived challenge.
	adi, err := open(ctx, state.Identifier)
	if err != nil {
		return nil, fmt.Errorf("open Store AMD provisioning runtime: %w", err)
	}
	defer func() { _ = adi.Close() }()
	// Provisioning must not inherit account cookies or forward identity headers
	// through redirects, even when a caller supplies its authenticated client.
	anonymous := *client
	anonymous.Jar = nil
	anonymous.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &anonymous
	_, deviceID := anisetteIdentityHeaders(state.Identifier)
	control := http.Header{
		"User-Agent": {"akd/1.0"}, "X-Mme-Device-Id": {deviceID},
		"X-Apple-I-MD-LU":         {base64.StdEncoding.EncodeToString([]byte(deviceID))},
		"X-Apple-Client-App-Name": {"akd"}, "X-Apple-I-TimeZone": {"UTC"},
		"X-Apple-Locale": {"en_US"}, "X-Apple-I-Client-Time": {time.Now().UTC().Format("2006-01-02T15:04:05Z")},
		"X-MMe-Client-Info": {"<MacBookPro18,3> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"},
	}
	bag, err := storeProvisioningRequest(ctx, client, storeProvisioningBag, control, nil)
	if err != nil {
		return nil, fmt.Errorf("get Store AMD provisioning bag: %w", err)
	}
	finishURL, err := provisioningString(bag, "amd-finish-provisioning")
	if err != nil || !appleProvisioningURL(finishURL) {
		return nil, errors.New("Store AMD bag contains no trusted finish endpoint")
	}
	lookup, err := storeProvisioningRequest(ctx, client, storeProvisioningLookup, control, nil)
	if err != nil {
		return nil, fmt.Errorf("get machine provisioning lookup: %w", err)
	}
	urls, _ := lookup["urls"].(map[string]any)
	startURL, err := provisioningString(urls, "midStartProvisioning")
	if err != nil || !appleProvisioningURL(startURL) {
		return nil, errors.New("machine lookup contains no trusted start endpoint")
	}
	started, err := storeProvisioningRequest(ctx, client, startURL, control, map[string]any{"Header": map[string]any{}, "Request": map[string]any{}})
	if err != nil {
		return nil, fmt.Errorf("start Store AMD provisioning: %w", err)
	}
	response, _ := started["Response"].(map[string]any)
	status, _ := response["Status"].(map[string]any)
	if !successfulProvisioningStatus(status["ec"]) {
		return nil, errors.New("Store AMD start provisioning was rejected")
	}
	spim, err := decodeProvisioningField(response, "spim")
	if err != nil {
		return nil, err
	}
	defer clear(spim)
	cpim, session, err := adi.StartProvisioning(storeAnisetteDSID, spim)
	if err != nil {
		return nil, fmt.Errorf("generate native Store AMD provisioning request: %w", err)
	}
	defer clear(cpim)
	finished, err := storeProvisioningRequest(ctx, client, finishURL, control, map[string]any{
		"clientData": base64.StdEncoding.EncodeToString(cpim), "guid": strings.ToUpper(hex.EncodeToString(hardwareID)),
	})
	if err != nil {
		return nil, fmt.Errorf("finish Store AMD provisioning: %w", err)
	}
	settingInfo, err := decodeProvisioningField(finished, "settingInfo")
	if err != nil {
		return nil, err
	}
	defer clear(settingInfo)
	transportKey, err := decodeProvisioningField(finished, "transportKey")
	if err != nil || len(transportKey) != 16 {
		return nil, errors.New("invalid Store AMD transport key")
	}
	defer clear(transportKey)
	if err := adi.EndProvisioning(session, settingInfo, transportKey); err != nil {
		return nil, fmt.Errorf("consume native Store AMD provisioning response: %w", err)
	}
	state.Provisioning, err = adi.State()
	if err != nil {
		return nil, fmt.Errorf("read native Store AMD state: %w", err)
	}
	return json.Marshal(state)
}

func appleProvisioningURL(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" || parsed.RawPath != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "apple.com" || strings.HasSuffix(host, ".apple.com")
}

func storeProvisioningRequest(ctx context.Context, client *http.Client, endpoint string, headers http.Header, payload map[string]any) (map[string]any, error) {
	if !appleProvisioningURL(endpoint) {
		return nil, errors.New("Store provisioning endpoint is not trusted")
	}
	method := http.MethodGet
	var body []byte
	var err error
	if payload != nil {
		method = http.MethodPost
		body, err = plist.Marshal(payload, plist.XMLFormat)
		if err != nil {
			return nil, errors.New("encode Store provisioning request")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create Store provisioning request")
	}
	request.Header = headers.Clone()
	request.Header.Set("Content-Type", "application/x-apple-plist")
	response, err := client.Do(request)
	if isUnknownAuthority(err) {
		if err := installAppleRoot(ctx, client); err != nil {
			return nil, err
		}
		retry := request.Clone(ctx)
		if request.GetBody != nil {
			retry.Body, err = request.GetBody()
			if err != nil {
				return nil, errors.New("recreate Store provisioning request body")
			}
		}
		response, err = client.Do(retry)
	}
	if err != nil {
		return nil, fmt.Errorf("send Store provisioning request: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, anisetteLimit+1))
	if err != nil || len(data) > anisetteLimit {
		return nil, errors.New("invalid Store provisioning response size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Store provisioning returned HTTP %d", response.StatusCode)
	}
	var decoded map[string]any
	if _, err := plist.Unmarshal(data, &decoded); err != nil {
		if err := json.Unmarshal(data, &decoded); err != nil || decoded == nil {
			return nil, errors.New("decode Store provisioning response")
		}
	}
	return decoded, nil
}

func successfulProvisioningStatus(value any) bool {
	switch number := value.(type) {
	case uint64:
		return number == 0
	case int64:
		return number == 0
	case float64:
		return number == 0
	default:
		return false
	}
}
