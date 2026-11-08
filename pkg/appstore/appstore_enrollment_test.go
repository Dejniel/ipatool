package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"go.uber.org/mock/gomock"
)

type enrollmentTestSession struct {
	events                  *[]string
	importError, closeError error
}

func (s *enrollmentTestSession) KBSync() ([]byte, error) {
	*s.events = append(*s.events, "kbsync")
	return []byte("fresh synthetic KBSync"), nil
}
func (s *enrollmentTestSession) Import(bag []byte) (map[string][]byte, error) {
	*s.events = append(*s.events, "import")
	if string(bag) != "synthetic keybag" {
		return nil, errors.New("wrong native response")
	}
	return map[string][]byte{"/var/db/fpsd/SC Info/SC Info.sidb": []byte("synthetic SIDB")}, s.importError
}
func (s *enrollmentTestSession) Close() error {
	*s.events = append(*s.events, "close")
	return s.closeError
}

func TestEnrollmentUsesOneLiveSessionWithoutRetryOrCachedBlob(t *testing.T) {
	for _, scenario := range []string{"success", "authorization failure", "expired session", "missing license", "missing keybag", "import failure", "close failure"} {
		t.Run(scenario, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			host := machine.NewMockMachine(ctrl)
			bags := http.NewMockClient[bagResult](ctrl)
			downloads := http.NewMockClient[downloadResult](ctrl)
			events := []string{}
			session := &enrollmentTestSession{events: &events}
			if scenario == "import failure" {
				session.importError = errors.New("native rejection")
			}
			if scenario == "close failure" {
				session.closeError = errors.New("native disposal failed")
			}
			host.EXPECT().MacAddress().Return("00:11:22:33:44:55", nil)
			bags.EXPECT().Send(gomock.Any()).Return(http.Result[bagResult]{StatusCode: 200, Data: bagResult{URLBag: urlBag{EntDownloadEndpoint: testEntDownloadEndpoint}}}, nil)
			downloads.EXPECT().Send(gomock.Any()).DoAndReturn(func(request http.Request) (http.Result[downloadResult], error) {
				events = append(events, "authorize")
				payload := request.Payload.(*http.XMLPayload).Content
				if payload["kbsync"] != base64.StdEncoding.EncodeToString([]byte("fresh synthetic KBSync")) || !request.NoRedirects {
					t.Fatal("authorization did not use the original live KBSync or blocked redirects")
				}
				if scenario == "authorization failure" {
					return http.Result[downloadResult]{}, errors.New("synthetic private token must not leak")
				}
				if scenario == "expired session" {
					return http.Result[downloadResult]{Data: downloadResult{FailureType: FailureTypeSignInRequired}}, nil
				}
				if scenario == "missing license" {
					return http.Result[downloadResult]{Data: downloadResult{FailureType: FailureTypeLicenseNotFound}}, nil
				}
				bag := []byte("synthetic keybag")
				if scenario == "missing keybag" {
					bag = nil
				}
				return http.Result[downloadResult]{StatusCode: 200, Data: downloadResult{Keybag: bag, Items: []downloadItemResult{{URL: "https://example.test/app.ipa", Sinfs: []Sinf{{ID: 0, Data: []byte("synthetic SINF")}}, Metadata: map[string]interface{}{"itemId": int64(42), "softwareVersionExternalIdentifier": "123", "softwareVersionBundleId": "example.test"}}}}}, nil
			})
			store := &appstore{machine: host, bagClient: bags, downloadClient: downloads, enrollmentFactory: func(ctx context.Context, hardware []byte, dsid uint64) (enrollmentSession, error) {
				events = append(events, "open")
				if _, ok := ctx.Deadline(); !ok || dsid != 1234 || !bytes.Equal(hardware, []byte{0, 17, 34, 51, 68, 85}) {
					t.Fatal("native session lost identity or deadline")
				}
				return session, nil
			}}
			out, err := store.Enroll(EnrollmentInput{Context: context.Background(), Account: Account{DirectoryServicesID: "1234", PasswordToken: "synthetic"}, App: App{ID: 42}, ExternalVersionID: "123"})
			want := []string{"open", "kbsync", "authorize", "import", "close"}
			if scenario == "authorization failure" || scenario == "missing keybag" || scenario == "expired session" || scenario == "missing license" {
				want = []string{"open", "kbsync", "authorize", "close"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("session lifetime: %v", events)
			}
			if scenario == "success" {
				if err != nil || len(out.Files) == 0 {
					t.Fatalf("missing export: %v", err)
				}
			} else {
				if err == nil || len(out.Files) != 0 {
					t.Fatal("failed enrollment returned usable material")
				}
			}
			if err != nil && bytes.Contains([]byte(err.Error()), []byte("private token")) {
				t.Fatal("private authorization diagnostic leaked")
			}
			if scenario == "expired session" && !errors.Is(err, ErrPasswordTokenExpired) {
				t.Fatal("lost typed session expiry")
			}
			if scenario == "missing license" && !errors.Is(err, ErrLicenseRequired) {
				t.Fatal("lost typed license error")
			}
		})
	}
}

func TestEnrollmentRejectsInvalidInputWithoutAccountOrNetwork(t *testing.T) {
	for _, input := range []EnrollmentInput{{}, {Context: context.Background(), App: App{ID: 42}}, {Context: context.Background(), App: App{ID: 42}, Account: Account{DirectoryServicesID: "1", PasswordToken: "synthetic"}, ExternalVersionID: "0"}} {
		if _, err := (&appstore{}).Enroll(input); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
