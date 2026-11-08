package machine

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/majd/ipatool/v2/internal/sap/unicorn"
)

var (
	errEnrollmentMessage  = errors.New("guest Mach call suspended")
	errEnrollmentWorker   = errors.New("guest worker suspended")
	errEnrollmentHardware = errors.New("guest service initialization reached hardware boundary")
)

type enrollmentThread struct{ entry, argument, output uint64 }
type enrollmentRequest struct {
	bytes             []byte
	pointer, capacity uint64
}

// enrollmentTransport schedules bounded native IPC and worker continuations
// inside one guest. It models Darwin transport/ownership, not cryptography.
type enrollmentTransport struct {
	guest         *Machine
	cf            *guestCFURLs
	files         *guestFiles
	loop          *guestRunLoop
	entitlements  map[string]bool
	versionHook   *unicorn.Hook
	owned         map[uint64]uint64
	completed     map[uint64]bool
	thread        *enrollmentThread
	nextThread    uint64
	request       *enrollmentRequest
	reply         []byte
	server        bool
	securityReady bool
}

func newEnrollmentTransport(guest *Machine, cf *guestCFURLs, files *guestFiles, commerce []byte) (*enrollmentTransport, error) {
	entitlements, err := enrollmentEntitlements(commerce)
	if err != nil {
		return nil, err
	}
	loop, err := installGuestRunLoop(cf)
	if err != nil {
		return nil, err
	}
	t := &enrollmentTransport{guest: guest, cf: cf, files: files, loop: loop, entitlements: entitlements,
		owned: make(map[uint64]uint64), completed: make(map[uint64]bool), nextThread: 0x7000}
	// The client/server version routines have the same ABI. Execute the native
	// service routine rather than synthesizing a version or successful reply.
	t.versionHook, err = guest.engine.AddCodeHook(coreFPBase+0x90c8, coreFPBase+0x90c8, func(uint64, uint32) {
		if err := guest.engine.RegWrite(unicorn.RegPC, enrollmentVersion); err != nil {
			guest.services.fail(err)
		}
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *enrollmentTransport) Initialize() error {
	g := t.guest.services
	if _, err := installGuestIOKit(t.cf); err != nil {
		return err
	}
	if _, err := installGuestBootstrap(g, []string{"com.apple.fairplayd", "com.apple.fpsd", "com.apple.unfreed", "com.apple.arcade.fpsd", "com.apple.fpsd.sim", "com.apple.fairplayd.xpc"}); err != nil {
		return err
	}
	address, err := g.resolve("_bootstrap_port")
	if err != nil {
		return err
	}
	if err := g.writeUint32(address, 0x1000); err != nil {
		return err
	}
	if err := t.cf.replace("_ptrace", func() error {
		request, err := g.argument(0)
		if err != nil {
			return err
		}
		if request != 31 {
			return errors.New("unsupported enrollment ptrace request")
		}
		return g.setResult(0)
	}); err != nil {
		return err
	}
	if err := t.cf.replace("_IOServiceMatching", func() error {
		pointer, err := g.argument(0)
		if err != nil {
			return err
		}
		name, err := g.readCString(pointer)
		if err != nil {
			return err
		}
		if name != "com_apple_driver_FairPlayIOKit" {
			return errors.New("unexpected enrollment hardware provider")
		}
		return errEnrollmentHardware
	}); err != nil {
		return err
	}
	t.guest.beginCall()
	program, err := t.guest.scratch([]byte("/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd\x00"), 128)
	if err != nil {
		return err
	}
	argv, err := t.guest.scratch(nil, 16)
	if err != nil {
		return err
	}
	if err := g.writeUint64(argv, program); err != nil {
		return err
	}
	_, err = t.guest.invoke(enrollmentMain, 1, argv, 0, 0)
	t.guest.clearScratch()
	if !errors.Is(err, errEnrollmentHardware) {
		return fmt.Errorf("initialize enrollment service: expected hardware boundary, got %v", err)
	}
	if _, err := installGuestBootstrap(g, []string{"com.apple.fpsd", "com.apple.fairplayd"}); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"_NDR_record": {0, 0, 0, 0, 1, 0, 0, 0}, "_mach_task_self_": {1, 16, 0, 0}} {
		address, err := g.resolve(name)
		if err != nil {
			return err
		}
		if err := g.engine.MemWrite(address, data); err != nil {
			return err
		}
	}
	for name, value := range map[string]uint64{"_vm_page_size": pageSize, "_vm_page_mask": pageSize - 1} {
		address, err := g.resolve(name)
		if err != nil {
			return err
		}
		if err := g.writeUint64(address, value); err != nil {
			return err
		}
	}
	for name, value := range map[string]uint64{"_mig_get_reply_port": 0x2100, "_voucher_mach_msg_set": 0, "_getpid": 501} {
		if err := t.cf.replace(name, func() error { return g.setResult(value) }); err != nil {
			return err
		}
	}
	if _, err := installGuestKqueues(g, 501); err != nil {
		return err
	}
	if _, err := t.guest.invoke(g.symbols["_kqueue"]); err != nil {
		return err
	}
	if err := t.files.installBackupMetadata(t.cf); err != nil {
		return err
	}
	for _, name := range []string{"_mach_msg", "_mach_msg_overwrite"} {
		if err := t.cf.replace(name, t.send); err != nil {
			return err
		}
	}
	if err := t.cf.replace("_pthread_create", t.createThread); err != nil {
		return err
	}
	if err := t.cf.replace("_pthread_detach", t.detachThread); err != nil {
		return err
	}
	if err := t.cf.replace("_mig_deallocate", t.deallocate); err != nil {
		return err
	}
	if err := t.cf.replace("_mach_msg_destroy", t.destroyMessage); err != nil {
		return err
	}
	for _, name := range []string{"_mig_put_reply_port", "_mig_dealloc_reply_port"} {
		if err := t.cf.replace(name, func() error {
			port, err := g.argument(0)
			if err != nil {
				return err
			}
			if port != 0x2100 {
				return errors.New("unknown enrollment reply port")
			}
			return g.setResult(0)
		}); err != nil {
			return err
		}
	}
	handle, err := t.cf.newObject(guestCFMachPortType, "", false)
	if err != nil {
		return err
	}
	t.loop.ports[handle] = guestMachCallback{port: 0x2000, callback: enrollmentCallback}
	return nil
}

func (t *enrollmentTransport) send() error {
	g := t.guest.services
	pointer, err := g.argument(0)
	if err != nil {
		return err
	}
	options, err := g.argument(1)
	if err != nil {
		return err
	}
	size, err := g.argument(2)
	if err != nil {
		return err
	}
	if size < 24 || size > 1<<20 || options&1 == 0 {
		return errors.New("invalid enrollment Mach send")
	}
	data, err := g.engine.MemRead(pointer, size)
	if err != nil {
		return err
	}
	if t.server {
		if len(t.reply) != 0 {
			return errors.New("duplicate enrollment Mach reply")
		}
		t.reply = data
		return g.setResult(0)
	}
	capacity, err := g.argument(3)
	if err != nil {
		return err
	}
	if options&2 == 0 || capacity < 24 || capacity > 1<<20 {
		return errors.New("invalid enrollment Mach receive")
	}
	t.request = &enrollmentRequest{bytes: data, pointer: pointer, capacity: capacity}
	return errEnrollmentMessage
}

func (t *enrollmentTransport) knownPort(port uint32) bool {
	for _, callback := range t.loop.ports {
		if callback.port == uint64(port) {
			return true
		}
	}
	return false
}

func (t *enrollmentTransport) Call(entry uint64, arguments ...uint64) (uint64, error) {
	result, err := t.guest.invoke(entry, arguments...)
	for count := 0; errors.Is(err, errEnrollmentMessage); count++ {
		if count >= 8 {
			return 0, errors.New("enrollment IPC exchange limit exceeded")
		}
		request := t.request
		t.request = nil
		if request == nil {
			return 0, errors.New("enrollment stopped without a Mach request")
		}
		client, saveErr := suspendGuestCall(t.guest)
		if saveErr != nil {
			return 0, saveErr
		}
		delivery, dispatchErr := t.dispatch(request.bytes)
		if dispatchErr != nil {
			client.clear()
			return 0, dispatchErr
		}
		if uint64(len(delivery)) > request.capacity {
			client.clear()
			return 0, errors.New("enrollment reply exceeds receive capacity")
		}
		t.server = false
		result, err = client.resumeAfterReturn(0, func() error { return t.guest.engine.MemWrite(request.pointer, delivery) })
		client.clear()
	}
	return result, err
}

func (t *enrollmentTransport) dispatch(sent []byte) ([]byte, error) {
	wire, owned, err := receiveGuestMachRequest(t.guest.services, sent, t.knownPort)
	if err != nil {
		return nil, err
	}
	for address, size := range owned {
		t.owned[address] = size
	}
	if !t.securityReady {
		if _, err := installGuestTaskEntitlements(t.cf, wire[len(sent)+20:], t.entitlements); err != nil {
			return nil, err
		}
		t.securityReady = true
	}
	port := binary.LittleEndian.Uint32(sent[8:])
	var handle uint64
	var target guestMachCallback
	for candidate, callback := range t.loop.ports {
		if callback.port == uint64(port) {
			handle, target = candidate, callback
			break
		}
	}
	if handle == 0 {
		return nil, errors.New("enrollment requested an unregistered port")
	}
	buffer, err := t.guest.services.allocate(uint64(len(wire)))
	if err != nil {
		return nil, err
	}
	defer t.guest.services.release(buffer)
	if err := t.guest.engine.MemWrite(buffer, wire); err != nil {
		return nil, err
	}
	t.server, t.reply = true, nil
	_, err = t.guest.invoke(target.callback, handle, buffer, uint64(len(wire)), target.info)
	for workers := 0; errors.Is(err, errEnrollmentWorker); workers++ {
		if workers >= 8 || t.thread == nil {
			return nil, errors.New("enrollment worker limit exceeded")
		}
		parent, saveErr := suspendGuestCall(t.guest)
		if saveErr != nil {
			return nil, saveErr
		}
		thread := *t.thread
		t.thread = nil
		_, workerErr := t.guest.invoke(thread.entry, thread.argument)
		if workerErr != nil {
			parent.clear()
			return nil, fmt.Errorf("run enrollment worker: %w", workerErr)
		}
		t.nextThread++
		token := t.nextThread
		t.completed[token] = true
		_, err = parent.resumeAfterReturn(0, func() error { return t.guest.services.writeUint64(thread.output, token) })
		parent.clear()
	}
	if err != nil {
		return nil, fmt.Errorf("dispatch enrollment request: %w", err)
	}
	if len(t.reply) == 0 {
		return nil, errors.New("enrollment service returned no reply")
	}
	delivery, owned, err := receiveGuestMachReply(t.guest.services, t.reply, binary.LittleEndian.Uint32(sent[12:]), t.knownPort)
	if err != nil {
		return nil, err
	}
	for address, size := range owned {
		t.owned[address] = size
	}
	return delivery, nil
}

func (t *enrollmentTransport) createThread() error {
	if !t.server || t.thread != nil {
		return errors.New("unexpected enrollment worker creation")
	}
	g := t.guest.services
	output, err := g.argument(0)
	if err != nil {
		return err
	}
	entry, err := g.argument(2)
	if err != nil {
		return err
	}
	argument, err := g.argument(3)
	if err != nil {
		return err
	}
	if output == 0 || entry == 0 {
		return errors.New("invalid enrollment worker")
	}
	t.thread = &enrollmentThread{entry: entry, argument: argument, output: output}
	return errEnrollmentWorker
}

func (t *enrollmentTransport) detachThread() error {
	token, err := t.guest.services.argument(0)
	if err != nil {
		return err
	}
	if !t.completed[token] {
		return errors.New("unknown enrollment worker")
	}
	delete(t.completed, token)
	return t.guest.services.setResult(0)
}

func (t *enrollmentTransport) deallocate() error {
	g := t.guest.services
	address, err := g.argument(0)
	if err != nil {
		return err
	}
	size, err := g.argument(1)
	if err != nil {
		return err
	}
	if expected, ok := t.owned[address]; !ok || address == 0 || size != expected {
		return errors.New("unowned enrollment Mach buffer")
	}
	if err := g.release(address); err != nil {
		return err
	}
	delete(t.owned, address)
	return g.setResult(0)
}

func (t *enrollmentTransport) destroyMessage() error {
	g := t.guest.services
	pointer, err := g.argument(0)
	if err != nil {
		return err
	}
	bits, err := g.readUint32(pointer)
	if err != nil {
		return err
	}
	if bits&0x80000000 != 0 {
		header, err := g.engine.MemRead(pointer, 44)
		if err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(header[24:]) != 1 || header[39] != 1 || binary.LittleEndian.Uint64(header[28:]) != 0 || binary.LittleEndian.Uint32(header[40:]) != 0 {
			return errors.New("unconsumed enrollment Mach descriptor")
		}
	}
	return g.setResult(0)
}

func (t *enrollmentTransport) Close() error {
	if t == nil {
		return nil
	}
	clear(t.reply)
	if t.versionHook != nil {
		err := t.versionHook.Close()
		t.versionHook = nil
		return err
	}
	return nil
}
