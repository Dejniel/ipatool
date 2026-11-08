package grandslam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"howett.net/plist"
)

type phone struct {
	ID         int    `json:"id"`
	Number     string `json:"numberWithDialCode"`
	Obfuscated string `json:"obfuscatedNumber"`
	PushMode   string `json:"pushMode"`
}

type verification struct {
	Phones  []phone `json:"trustedPhoneNumbers"`
	Current *phone  `json:"trustedPhoneNumber"`
}

type authOptions struct {
	verification
	Verification     verification `json:"phoneNumberVerification"`
	NoTrustedDevices *bool        `json:"noTrustedDevices"`
}

func (c *Client) methods(ctx context.Context, pending *challenge) ([]Method, *Method, error) {
	status, data, err := c.request(ctx, http.MethodGet, "/auth", "application/json", pending.identity, nil)
	if err != nil {
		// A failed phone lookup must not discard an available trusted-device path.
		if pending.trustedDevice {
			return []Method{{Kind: "device", Label: "Trusted Apple device (phone list unavailable)"}}, nil, nil
		}
		return nil, nil, err
	}
	var options authOptions
	if err := json.Unmarshal(data, &options); err != nil {
		return nil, nil, errors.New("decode Apple 2FA delivery options")
	}
	phones := append(options.Phones, options.Verification.Phones...)
	for _, current := range []*phone{options.Current, options.Verification.Current} {
		if current != nil {
			phones = append(phones, *current)
		}
	}
	var methods []Method
	seen := make(map[int]bool)
	for _, entry := range phones {
		if entry.ID < 1 || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		number := entry.Number
		if number == "" {
			number = entry.Obfuscated
		}
		if number == "" {
			number = fmt.Sprintf("trusted number %d", entry.ID)
		}
		// Only display Apple's masked label, with no terminal control characters.
		number = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, number)
		if len(number) > 160 {
			number = "trusted phone number"
		}
		if entry.PushMode != "voice" {
			methods = append(methods, Method{"sms", entry.ID, "SMS to " + number})
		}
		methods = append(methods, Method{"voice", entry.ID, "Phone call to " + number})
	}
	if pending.trustedDevice && (options.NoTrustedDevices == nil || !*options.NoTrustedDevices) {
		methods = append(methods, Method{Kind: "device", Label: "Trusted Apple device"})
	}
	if len(methods) == 0 {
		return nil, nil, errors.New("Apple returned no selectable 2FA delivery methods")
	}
	var delivered *Method
	// HTTP 201 can already send a code. Reuse it only if Apple identifies the
	// exact destination and mode; never infer that it was phones[0].
	current := options.Current
	if current == nil {
		current = options.Verification.Current
	}
	if status == http.StatusCreated && current != nil {
		for _, method := range methods {
			if method.PhoneID == current.ID && method.Kind == current.PushMode {
				match := method
				delivered = &match
				break
			}
		}
	}
	return methods, delivered, nil
}

func (c *Client) verify(ctx context.Context, pending *challenge, prompts Prompts) error {
	methods, delivered, err := c.methods(ctx, pending)
	if err != nil {
		return err
	}
	index, err := prompts.Select(append([]Method(nil), methods...))
	if err != nil {
		return err
	}
	if index < 0 || index >= len(methods) {
		return errors.New("invalid 2FA delivery selection")
	}
	method := methods[index]
	payload := map[string]any{"phoneNumber": map[string]int{"id": method.PhoneID}, "mode": method.Kind}
	if delivered == nil || delivered.Kind != method.Kind || delivered.PhoneID != method.PhoneID {
		if method.Kind == "device" {
			_, _, err = c.request(ctx, http.MethodGet, "/auth/verify/trusteddevice", "text/x-xml-plist", pending.identity, nil)
		} else {
			err = c.jsonRequest(ctx, http.MethodPut, "/auth/verify/phone", pending, payload)
		}
		if err != nil {
			return err
		}
	}
	code, err := prompts.Code()
	if err != nil {
		return err
	}
	code = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(code))
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
		return errors.New("2FA code must contain exactly six digits")
	}
	if method.Kind != "device" {
		payload["securityCode"] = map[string]string{"code": code}
		return c.jsonRequest(ctx, http.MethodPost, "/auth/verify/phone/securitycode", pending, payload)
	}
	headers := c.headers.Clone()
	c.headers.Set("security-code", code)
	defer func() { c.headers = headers }()
	_, data, err := c.request(ctx, http.MethodGet, "/grandslam/GsService2/validate", "text/x-xml-plist", pending.identity, nil)
	if err != nil {
		return err
	}
	var result map[string]any
	if _, err := plist.Unmarshal(data, &result); err != nil {
		return errors.New("decode trusted-device 2FA result")
	}
	return checkStatus(result)
}
