package machine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

func TestEnrollmentRejectsInvalidInputsBeforeLoadingRuntime(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		ctx      context.Context
		hardware []byte
		dsid     uint64
	}{
		{nil, make([]byte, 6), 1}, {context.Background(), nil, 1},
		{context.Background(), make([]byte, 6), 0}, {canceled, make([]byte, 6), 1},
		{context.Background(), make([]byte, 6), 1},
	} {
		if _, err := OpenEnrollment(input.ctx, assets.Bundle{}, input.hardware, input.dsid); err == nil {
			t.Fatal("invalid enrollment input accepted")
		}
	}
}

func TestEnrollmentRequiresFreshSessionAndConsumesResponseOnce(t *testing.T) {
	s := &EnrollmentSession{ctx: context.Background(), agent: &StoreAgent{guest: newServiceTestMachine(t)}}
	if _, err := s.Import(make([]byte, 8)); err == nil {
		t.Fatal("import accepted without KBSync")
	}
	s.phase = enrollmentGenerated
	if _, err := s.KBSync(); err == nil {
		t.Fatal("KBSync regenerated in the same session")
	}
	if _, err := s.Import(nil); err == nil {
		t.Fatal("empty keybag accepted")
	}
	if _, err := s.Import(make([]byte, 8)); err == nil {
		t.Fatal("failed import was replayed")
	}
}

// No account, keychain or authorization request is involved. With a warm asset
// cache this check is entirely offline; opt in explicitly before running it.
func TestLiveEnrollmentRuntime(t *testing.T) {
	if os.Getenv("IPATOOL_ENROLLMENT_RUNTIME_TEST") != "1" {
		t.Skip("explicit native enrollment runtime check required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := assets.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenEnrollment(ctx, bundle, []byte{0, 17, 34, 51, 68, 85}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	blob, err := s.KBSync()
	if err != nil || len(blob) == 0 {
		t.Fatalf("native KBSync: %v", err)
	}
	clear(blob)
	transport, err := s.openService()
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("native generator and enrollment service initialized; no credentials or network authorization used")
}

// A captured reply belongs to the original live generator, not a fresh guest.
// The private fixture is opt-in and never becomes a committed test vector.
func TestLiveEnrollmentRejectsReplayedResponse(t *testing.T) {
	inputPath, responsePath := os.Getenv("IPATOOL_ENROLLMENT_REPLAY_INPUT"), os.Getenv("IPATOOL_ENROLLMENT_REPLAY_RESPONSE")
	if inputPath == "" || responsePath == "" {
		t.Skip("explicit private replay fixture required")
	}
	read := func(path string) []byte {
		t.Helper()
		info, err := os.Lstat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
			t.Fatal("invalid private replay fixture")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("read replay fixture")
		}
		return data
	}
	var input struct {
		Hardware []byte `json:"hardware"`
		Account  uint64 `json:"account"`
	}
	data := read(inputPath)
	err := json.Unmarshal(data, &input)
	clear(data)
	if err != nil {
		t.Fatal("invalid generator metadata")
	}
	var response struct {
		Keybag []byte `json:"keybag"`
	}
	data = read(responsePath)
	err = json.Unmarshal(data, &response)
	clear(data)
	if err != nil || len(response.Keybag) == 0 {
		t.Fatal("invalid response metadata")
	}
	defer clear(response.Keybag)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := assets.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenEnrollment(ctx, bundle, input.Hardware, input.Account)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	blob, err := s.KBSync()
	if err != nil {
		t.Fatal(err)
	}
	clear(blob)
	_, err = s.Import(response.Keybag)
	if err == nil || !strings.Contains(err.Error(), "native status") {
		t.Fatalf("replay did not reach a native rejection: %v", err)
	}
	t.Logf("captured response rejected by a different native session: %v", err)
}
