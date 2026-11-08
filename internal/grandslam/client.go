// Package grandslam implements selectable Apple 2FA without retaining challenge
// tokens or codes. It does not own the saved App Store account or Store AMD state.
package grandslam

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"howett.net/plist"
)

const (
	endpoint      = "https://gsa.apple.com"
	responseLimit = 1 << 20
	userAgent     = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0"
)

type Method struct {
	Kind    string
	PhoneID int
	Label   string
}

// Prompts are caller-owned. Select must return an index from the offered list;
// Code is called only after Apple accepts the selected delivery request.
type Prompts struct {
	Select func([]Method) (int, error)
	Code   func() (string, error)
}

type Client struct {
	http    *http.Client
	headers http.Header
	base    string
}

func New(client *http.Client, headers http.Header) *Client {
	bounded := *client
	bounded.Timeout = 30 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{&bounded, headers.Clone(), endpoint}
}

type challenge struct {
	identity      string
	trustedDevice bool
}

// Authenticate returns only the password-equivalent token needed by the Store
// bridge. The original password remains the credential saved by that bridge.
func (c *Client) Authenticate(ctx context.Context, email, password string, prompts Prompts) (string, error) {
	if prompts.Select == nil || prompts.Code == nil {
		return "", errors.New("GrandSlam 2FA prompts are required")
	}
	for attempt := 0; attempt < 2; attempt++ {
		pet, pending, err := c.authenticate(ctx, email, password)
		if err != nil {
			return "", err
		}
		if pending == nil {
			return pet, nil
		}
		if attempt != 0 {
			return "", errors.New("Apple still requires verification after accepting the 2FA code")
		}
		if err := c.verify(ctx, pending, prompts); err != nil {
			return "", err
		}
	}
	return "", errors.New("GrandSlam authentication did not complete")
}

func (c *Client) authenticate(ctx context.Context, email, password string) (string, *challenge, error) {
	if email == "" || len(email) > 4096 || password == "" || len(password) > 4096 {
		return "", nil, errors.New("invalid GrandSlam credentials")
	}
	srp, err := newSRP()
	if err != nil {
		return "", nil, err
	}
	initial, err := c.post(ctx, map[string]any{"A2k": srp.public.Bytes(), "o": "init", "ps": []string{"s2k", "s2k_fo"}, "u": email})
	if err != nil {
		return "", nil, err
	}
	salt, _ := initial["s"].([]byte)
	server, _ := initial["B"].([]byte)
	rounds, ok := initial["i"].(uint64)
	if !ok || rounds < 1 || rounds > 1_000_000 {
		return "", nil, errors.New("invalid GrandSlam iteration count")
	}
	cookie, _ := initial["c"].(string)
	protocol, _ := initial["sp"].(string)
	if cookie == "" {
		return "", nil, errors.New("missing GrandSlam challenge cookie")
	}
	proof, err := srp.complete(email, password, salt, server, int(rounds), protocol)
	if err != nil {
		return "", nil, err
	}
	defer clear(proof.key)
	complete, err := c.post(ctx, map[string]any{"M1": proof.m1, "c": cookie, "o": "complete", "u": email})
	if err != nil {
		return "", nil, err
	}
	m2, _ := complete["M2"].([]byte)
	spd, _ := complete["spd"].([]byte)
	plain, err := proof.decrypt(m2, spd)
	if err != nil {
		return "", nil, err
	}
	defer clear(plain)
	var values map[string]any
	if _, err := plist.Unmarshal(plain, &values); err != nil {
		return "", nil, errors.New("decode GrandSlam account data")
	}
	status, _ := complete["Status"].(map[string]any)
	au, _ := status["au"].(string)
	if au == "secondaryAuth" || au == "trustedDeviceSecondaryAuth" {
		adsid, _ := values["adsid"].(string)
		idms, _ := values["GsIdmsToken"].(string)
		if adsid == "" || idms == "" {
			return "", nil, errors.New("missing GrandSlam 2FA identity")
		}
		return "", &challenge{base64.StdEncoding.EncodeToString([]byte(adsid + ":" + idms)), au == "trustedDeviceSecondaryAuth"}, nil
	}
	if au != "" {
		return "", nil, errors.New("unsupported GrandSlam authentication challenge")
	}
	tokens, _ := values["t"].(map[string]any)
	pet, _ := tokens["com.apple.gs.idms.pet"].(map[string]any)
	value, _ := pet["token"].(string)
	if value == "" {
		return "", nil, errors.New("GrandSlam returned no Store password-equivalent token")
	}
	return strings.Clone(value), nil, nil
}

func (c *Client) post(ctx context.Context, fields map[string]any) (map[string]any, error) {
	cpd := map[string]any{"bootstrap": "true", "icscrec": "true", "loc": "en_GB", "pbe": "false", "prkgen": "true", "svct": "iCloud"}
	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-LU", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale", "X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info"} {
		cpd[key] = c.headers.Get(key)
	}
	fields["cpd"] = cpd
	body, err := plist.Marshal(map[string]any{"Header": map[string]string{"Version": "1.0.1"}, "Request": fields}, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("encode GrandSlam request")
	}
	_, data, err := c.request(ctx, http.MethodPost, "/grandslam/GsService2", "text/x-xml-plist", "", body)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Response map[string]any `plist:"Response"`
	}
	if _, err := plist.Unmarshal(data, &envelope); err != nil || envelope.Response == nil {
		return nil, errors.New("decode GrandSlam response")
	}
	if err := checkStatus(envelope.Response); err != nil {
		return nil, err
	}
	return envelope.Response, nil
}

func checkStatus(values map[string]any) error {
	if status, ok := values["Status"].(map[string]any); ok {
		values = status
	}
	switch code := values["ec"].(type) {
	case uint64:
		if code == 0 {
			return nil
		}
		return fmt.Errorf("GrandSlam server error %d", int64(code))
	case int64:
		if code == 0 {
			return nil
		}
		return fmt.Errorf("GrandSlam server error %d", code)
	default:
		return errors.New("missing GrandSlam result status")
	}
}

func (c *Client) request(ctx context.Context, method, path, contentType, identity string, body []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("create GrandSlam request")
	}
	request.Header = c.headers.Clone()
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", contentType)
	request.Header.Set("Content-Type", contentType)
	if identity != "" {
		request.Header.Set("User-Agent", "Xcode")
		request.Header.Set("X-Apple-Identity-Token", identity)
		request.Header.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, errors.New("GrandSlam request failed; check connectivity or retry later")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, nil, fmt.Errorf("GrandSlam %s returned HTTP %d", path, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(data) > responseLimit {
		return 0, nil, errors.New("invalid GrandSlam response size or read failure")
	}
	return response.StatusCode, data, nil
}

func (c *Client) jsonRequest(ctx context.Context, verb, path string, pending *challenge, payload any) error {
	var data []byte
	if payload != nil {
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			return errors.New("encode GrandSlam 2FA request")
		}
	}
	_, _, err := c.request(ctx, verb, path, "application/json", pending.identity, data)
	return err
}
