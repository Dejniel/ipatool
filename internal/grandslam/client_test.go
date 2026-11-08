package grandslam

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestSelectablePhoneAuthentication(t *testing.T) {
	var key, aPublic, m1 []byte
	verified, handshakes, codeReads := false, 0, 0
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		writePlist := func(value any) {
			data, err := plist.Marshal(value, plist.XMLFormat)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(data)
		}
		if r.URL.Path != "/grandslam/GsService2" {
			if r.Header.Get("X-Apple-Identity-Token") == "" {
				t.Error("missing 2FA identity")
			}
			switch r.URL.Path {
			case "/auth":
				_, _ = io.WriteString(w, `{"trustedPhoneNumbers":[{"id":7,"numberWithDialCode":"***12","pushMode":"sms"},{"id":11,"numberWithDialCode":"***34","pushMode":"voice"}],"noTrustedDevices":true}`)
			case "/auth/verify/phone", "/auth/verify/phone/securitycode":
				var payload struct {
					Phone struct {
						ID int `json:"id"`
					} `json:"phoneNumber"`
					Mode string `json:"mode"`
					Code struct {
						Code string `json:"code"`
					} `json:"securityCode"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if payload.Phone.ID != 11 || payload.Mode != "voice" {
					t.Error("selected destination or mode changed")
				}
				if r.URL.Path == "/auth/verify/phone/securitycode" {
					if payload.Code.Code != "123456" {
						t.Error("wrong verification code")
					}
					verified = true
				}
				w.WriteHeader(204)
			default:
				t.Errorf("unexpected endpoint %s", r.URL.Path)
				w.WriteHeader(404)
			}
			return
		}
		data, _ := io.ReadAll(r.Body)
		var envelope struct {
			Request map[string]any `plist:"Request"`
		}
		if _, err := plist.Unmarshal(data, &envelope); err != nil {
			t.Error(err)
			return
		}
		fields := envelope.Request
		cpd, _ := fields["cpd"].(map[string]any)
		if cpd["X-Apple-I-MD"] != "synthetic-proof" {
			t.Error("missing exact-case anisette header in cpd")
		}
		switch fields["o"] {
		case "init":
			handshakes++
			aPublic = fields["A2k"].([]byte)
			// Independent server side SRP: S=(A*v^u)^b mod N.
			n, _ := new(big.Int).SetString(modulusHex, 16)
			g, b := big.NewInt(2), big.NewInt(9)
			salt := []byte("synthetic salt")
			derived, _ := passwordKey("test-password", salt, 17, "s2k")
			x := new(big.Int).SetBytes(hash(salt, hash([]byte(":"), derived)))
			v := new(big.Int).Exp(g, x, n)
			gp := g.FillBytes(make([]byte, 256))
			k := new(big.Int).SetBytes(hash(n.Bytes(), gp))
			serverKey := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, n)), n)
			u := new(big.Int).SetBytes(hash(aPublic, serverKey.Bytes()))
			base := new(big.Int).Mul(new(big.Int).SetBytes(aPublic), new(big.Int).Exp(v, u, n))
			key = hash(new(big.Int).Exp(base, b, n).Bytes())
			xor := hash(n.Bytes())
			for i, value := range hash(gp) {
				xor[i] ^= value
			}
			m1 = hash(xor, hash([]byte("test@example.test")), salt, aPublic, serverKey.Bytes(), key)
			writePlist(map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": 0}, "s": salt, "B": serverKey.Bytes(), "i": 17, "c": "synthetic-cookie", "sp": "s2k"}})
		case "complete":
			if !bytes.Equal(fields["M1"].([]byte), m1) {
				t.Error("client proof mismatch")
			}
			values := map[string]any{"adsid": "123", "GsIdmsToken": "never-print-this-token"}
			status := map[string]any{"ec": 0}
			if !verified {
				status["au"] = "secondaryAuth"
			} else {
				values["t"] = map[string]any{"com.apple.gs.idms.pet": map[string]string{"token": "synthetic-pet"}}
			}
			plain, _ := plist.Marshal(values, plist.BinaryFormat)
			padding := aes.BlockSize - len(plain)%aes.BlockSize
			plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
			derive := func(label string) []byte {
				h := hmac.New(sha256.New, key)
				_, _ = h.Write([]byte(label))
				return h.Sum(nil)
			}
			block, _ := aes.NewCipher(derive("extra data key:"))
			cipher.NewCBCEncrypter(block, derive("extra data iv:")[:16]).CryptBlocks(plain, plain)
			writePlist(map[string]any{"Response": map[string]any{"Status": status, "M2": hash(aPublic, m1, key), "spd": plain}})
		default:
			t.Error("unknown SRP operation")
		}
	}))
	defer server.Close()
	c := New(server.Client(), http.Header{"X-Apple-I-Md": {"synthetic-proof"}})
	c.base = server.URL
	pet, err := c.Authenticate(context.Background(), "test@example.test", "test-password", Prompts{
		Select: func(methods []Method) (int, error) {
			want := []Method{{"sms", 7, "SMS to ***12"}, {"voice", 7, "Phone call to ***12"}, {"voice", 11, "Phone call to ***34"}}
			if !reflect.DeepEqual(methods, want) {
				t.Errorf("methods: %#v", methods)
			}
			return 2, nil
		},
		Code: func() (string, error) { codeReads++; return "123 456", nil },
	})
	if err != nil || pet != "synthetic-pet" || handshakes != 2 || codeReads != 1 {
		t.Fatalf("authentication: %q, %v, %d handshakes, %d prompts", pet, err, handshakes, codeReads)
	}
	if len(calls) != 7 {
		t.Fatalf("unexpected flow: %v", calls)
	}
}

func TestDeliveryGuards(t *testing.T) {
	for _, test := range []struct {
		name, json     string
		status, choice int
		want           []string
	}{
		{"second phone", `{"phoneNumberVerification":{"trustedPhoneNumbers":[{"id":5,"numberWithDialCode":"***11"},{"id":9,"numberWithDialCode":"***22"}]}}`, 200, 2, []string{"GET /auth", "PUT /auth/verify/phone", "POST /auth/verify/phone/securitycode"}},
		{"already delivered", `{"trustedPhoneNumbers":[{"id":9}],"trustedPhoneNumber":{"id":9,"pushMode":"sms"}}`, 201, 0, []string{"GET /auth", "POST /auth/verify/phone/securitycode"}},
		{"invalid selection", `{"trustedPhoneNumbers":[{"id":9}]}`, 200, 20, []string{"GET /auth"}},
		{"empty options", `{}`, 200, 0, []string{"GET /auth"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.URL.Path == "/auth" {
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.json)
				} else {
					w.WriteHeader(204)
				}
			}))
			defer server.Close()
			c := New(server.Client(), make(http.Header))
			c.base = server.URL
			err := c.verify(context.Background(), &challenge{identity: "synthetic"}, Prompts{
				Select: func([]Method) (int, error) { return test.choice, nil },
				Code:   func() (string, error) { return "123456", nil },
			})
			if (err != nil) != (len(test.want) == 1) {
				t.Fatalf("verification: %v", err)
			}
			if !reflect.DeepEqual(calls, test.want) {
				t.Errorf("requests: %v, want %v", calls, test.want)
			}
		})
	}
}

func TestPrivateErrorsAndNoRedirectReplay(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "/secret")
		w.WriteHeader(302)
		_, _ = fmt.Fprint(w, "secret token do not print")
	}))
	defer server.Close()
	c := New(server.Client(), make(http.Header))
	c.base = server.URL
	_, _, err := c.request(context.Background(), "POST", "/auth", "application/json", "identity", []byte("code"))
	if err == nil || strings.Contains(err.Error(), "secret") || calls != 1 {
		t.Fatalf("unsafe redirect or diagnostics: %v", err)
	}
	if err := checkStatus(map[string]any{"ec": uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := checkStatus(map[string]any{"ec": int64(-42), "em": "secret"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unsafe service error")
	}
}
