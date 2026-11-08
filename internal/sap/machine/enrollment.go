package machine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"sync"

	macho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/sap/machimage"
	"howett.net/plist"
)

// These entry points belong to the hash-pinned macOS 27 commerce/fairplayd
// profile. They are not discovered or guessed for arbitrary Apple binaries.
const (
	enrollmentServiceBase = uint64(0x0000100100000000)
	enrollmentMain        = enrollmentServiceBase + 0x332040
	enrollmentCallback    = enrollmentServiceBase + 0x3439bc
	enrollmentVersion     = enrollmentServiceBase + 0x7408
	enrollmentImport      = storeAgentBase + 0x16e0f8
)

// EnrollmentSession owns one live native generator and its in-memory FairPlay
// service. Its KBSync and the authorization reply must never cross sessions.
// All guest file operations are isolated from the host filesystem/key stores.
type EnrollmentSession struct {
	mu     sync.Mutex
	ctx    context.Context
	agent  *StoreAgent
	cf     *guestCFURLs
	files  *guestFiles
	bundle assets.Bundle
	dsid   uint64
	phase  enrollmentPhase
}

type enrollmentPhase uint8

const (
	enrollmentOpened enrollmentPhase = iota
	enrollmentGenerated
	enrollmentConsumed
	enrollmentClosed
)

func OpenEnrollment(ctx context.Context, bundle assets.Bundle, hardware []byte, dsid uint64) (*EnrollmentSession, error) {
	if ctx == nil || dsid == 0 {
		return nil, errors.New("enrollment requires a context and nonzero account DSID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := hardwareBlock(hardware)
	if err != nil {
		return nil, err
	}
	if err := assets.Validate(bundle); err != nil {
		return nil, fmt.Errorf("validate native enrollment profile: %w", err)
	}
	version, err := assets.SystemVersion()
	if err != nil {
		return nil, err
	}
	guest, exports, err := openRuntime(ctx, bundle, runtimeOptions{
		extraImages: []imageSpec{{name: "commerce", data: bundle.Commerce, base: storeAgentBase}},
		shims:       shimOptions{zeroReturnAliases: storeAgentZeroReturnAliases},
	})
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = guest.Close()
		}
	}()
	guest.entry.dispose = exports["_jEHf8Xzsv8K"]
	s := &EnrollmentSession{ctx: ctx, dsid: dsid, bundle: bundle, agent: &StoreAgent{guest: guest}}
	if s.cf, err = installGuestCFURL(guest.services, map[string][]byte{"/System/Library/CoreServices/SystemVersion.plist": version}); err != nil {
		return nil, err
	}
	if err := installGuestLibc(guest.services); err != nil {
		return nil, err
	}
	if s.files, err = installGuestFiles(guest.services); err != nil {
		return nil, err
	}
	if _, err := installGuestBootstrap(guest.services, nil); err != nil {
		return nil, err
	}
	if s.agent.global, err = s.agent.initializeGlobal(block); err != nil {
		return nil, err
	}
	ready = true
	return s, nil
}

func (s *EnrollmentSession) KBSync() ([]byte, error) {
	if s == nil {
		return nil, errors.New("enrollment session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agent == nil || s.ctx == nil {
		return nil, errors.New("enrollment session is not initialized")
	}
	if s.phase != enrollmentOpened {
		return nil, errors.New("enrollment KBSync can be generated only once")
	}
	s.phase = enrollmentConsumed
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	blob, err := s.agent.guest.generateKBSync(storeAgentKBSyncEntry, s.agent.global, s.dsid)
	if err != nil {
		return nil, err
	}
	s.phase = enrollmentGenerated
	return blob, nil
}

// Import consumes one matching authorization response and returns only the
// generated SC Info files. The caller owns the returned copies and must keep
// them private. No decryption, network requests or account persistence occur.
func (s *EnrollmentSession) Import(keybag []byte) (map[string][]byte, error) {
	if s == nil {
		return nil, errors.New("enrollment session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agent == nil || s.ctx == nil {
		return nil, errors.New("enrollment session is not initialized")
	}
	if s.phase != enrollmentGenerated {
		return nil, errors.New("enrollment import requires this session's fresh KBSync")
	}
	s.phase = enrollmentConsumed
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if len(keybag) < 8 || len(keybag) > 1<<20 {
		return nil, errors.New("invalid enrollment keybag extent")
	}
	transport, err := s.openService()
	if err != nil {
		return nil, fmt.Errorf("prepare enrollment service: %w", err)
	}
	defer transport.Close()
	guest := s.agent.guest
	guest.beginCall()
	defer guest.clearScratch()
	input, err := guest.scratch(keybag, uint64(len(keybag)))
	if err != nil {
		return nil, err
	}
	status, err := transport.Call(enrollmentImport, uint64(s.agent.global), input, uint64(len(keybag)))
	if err != nil {
		return nil, fmt.Errorf("import enrollment keybag: %w", err)
	}
	if int32(status) != 0 {
		return nil, fmt.Errorf("import enrollment keybag: native status %d", int32(status))
	}
	files := make(map[string][]byte)
	for name, file := range s.files.files {
		if len(file.data) != 0 && (path.Base(name) == "SC Info.sidb" || path.Base(name) == "SC Info.sids") {
			files[name] = bytes.Clone(file.data)
		}
	}
	if len(files["/var/db/fpsd/SC Info/SC Info.sidb"]) == 0 {
		return nil, errors.New("native enrollment returned success without a server SIDB")
	}
	return files, nil
}

func (s *EnrollmentSession) openService() (*enrollmentTransport, error) {
	guest := s.agent.guest.services
	image, err := machimage.Open("fairplayd", s.bundle.FairPlayD)
	if err != nil {
		return nil, err
	}
	if err := image.Relocate(enrollmentServiceBase, guest.resolve); err != nil {
		return nil, err
	}
	if err := image.Load(guest.engine); err != nil {
		return nil, err
	}
	transport, err := newEnrollmentTransport(s.agent.guest, s.cf, s.files, s.bundle.Commerce)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = transport.Close()
		}
	}()
	if err := transport.Initialize(); err != nil {
		return nil, err
	}
	ready = true
	return transport, nil
}

func (s *EnrollmentSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == enrollmentClosed {
		return nil
	}
	s.phase = enrollmentClosed
	if s.files != nil {
		for _, file := range s.files.files {
			clear(file.data)
		}
	}
	// A failed native operation may leave a suspended stack. Engine disposal
	// must not invoke another native destructor on that stack.
	if s.agent == nil || s.agent.guest == nil {
		return nil
	}
	return s.agent.guest.Close()
}

func enrollmentEntitlements(commerce []byte) (map[string]bool, error) {
	fat, err := macho.NewFatFile(bytes.NewReader(commerce))
	if err != nil {
		return nil, err
	}
	// Read metadata from the same pinned architecture used by the runtime.
	var image *macho.File
	for _, arch := range fat.Arches {
		if arch.CPU == types.CPUArm64 && arch.SubCPU&types.CpuSubtypeMask == types.CPUSubtypeArm64E {
			image = arch.File
			break
		}
	}
	var signed map[string]any
	if image == nil || image.CodeSignature() == nil {
		return nil, errors.New("commerce profile has no signed entitlements")
	}
	if _, err := plist.Unmarshal([]byte(image.CodeSignature().Entitlements), &signed); err != nil {
		return nil, err
	}
	values := make(map[string]bool)
	for name, value := range signed {
		if flag, ok := value.(bool); ok {
			values[name] = flag
		}
	}
	return values, nil
}
