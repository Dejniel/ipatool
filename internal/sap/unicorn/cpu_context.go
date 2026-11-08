package unicorn

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// CPU-only state for this engine, not a portable checkpoint or memory snapshot.
// The runtime never enables Unicorn's optional memory-context mode.
type CPUState struct {
	owner *Engine
	mu    sync.Mutex
	data  []byte
}

func (e *Engine) SaveCPU() (*CPUState, error) {
	handle, done, err := e.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	var size func(uintptr) uintptr
	var allocate func(uintptr, **byte) int32
	var save func(uintptr, *byte) int32
	var free func(*byte) int32
	purego.RegisterLibFunc(&size, e.library.handle, "uc_context_size")
	purego.RegisterLibFunc(&allocate, e.library.handle, "uc_context_alloc")
	purego.RegisterLibFunc(&save, e.library.handle, "uc_context_save")
	purego.RegisterLibFunc(&free, e.library.handle, "uc_context_free")
	length := size(handle)
	if length == 0 || length > 1<<20 {
		return nil, errors.New("invalid Unicorn CPU context size")
	}
	var native *byte
	if err := e.err(allocate(handle, &native)); err != nil {
		return nil, err
	}
	if native == nil {
		return nil, errors.New("Unicorn returned an empty CPU context")
	}
	defer free(native)
	if err := e.err(save(handle, native)); err != nil {
		return nil, err
	}
	// uc_context_alloc initializes the private header. Preserve it instead of
	// guessing the structure; only Go-owned bytes survive this function.
	data := bytes.Clone(unsafe.Slice(native, int(length)))
	return &CPUState{owner: e, data: data}, nil
}

func (e *Engine) RestoreCPU(state *CPUState) error {
	if state == nil || state.owner != e {
		return errors.New("CPU context belongs to another engine")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.data) == 0 {
		return errors.New("CPU context has been cleared")
	}
	handle, done, err := e.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	var restore func(uintptr, unsafe.Pointer) int32
	purego.RegisterLibFunc(&restore, e.library.handle, "uc_context_restore")
	err = e.err(restore(handle, unsafe.Pointer(unsafe.SliceData(state.data))))
	runtime.KeepAlive(state)
	return err
}

func (state *CPUState) Clear() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	clear(state.data)
	state.data = nil
}
