package machine

import (
	"errors"

	"github.com/majd/ipatool/v2/internal/sap/unicorn"
)

type guestSuspendedCall struct {
	guest     *Machine
	cpu       *unicorn.CPUState
	stack     []byte
	callbacks []uint64
	link      uint64
	used      bool
}

func suspendGuestCall(guest *Machine) (*guestSuspendedCall, error) {
	cpu, err := guest.engine.SaveCPU()
	if err != nil {
		return nil, err
	}
	stack, err := guest.engine.MemRead(stackBase, stackSize)
	if err != nil {
		cpu.Clear()
		return nil, err
	}
	link, err := guest.engine.RegRead(unicorn.RegLR)
	if err != nil {
		cpu.Clear()
		clear(stack)
		return nil, err
	}
	return &guestSuspendedCall{guest: guest, cpu: cpu, stack: stack, callbacks: append([]uint64(nil), guest.services.callbackReturns...), link: link}, nil
}

func (call *guestSuspendedCall) clear() {
	call.cpu.Clear()
	clear(call.stack)
	call.stack = nil
	clear(call.callbacks)
	call.callbacks = nil
}

// Restore only the suspended stack, never server heap/state changes. The
// continuation stub lets the normal invoke loop keep its timeout and ARM64
// compatibility handling, without recreating argument registers or a frame.
func (call *guestSuspendedCall) resumeAfterReturn(result uint64, deliver func() error) (uint64, error) {
	if call.used || len(call.stack) != int(stackSize) {
		return 0, errors.New("suspended guest call cannot be resumed twice")
	}
	call.used = true
	guest := call.guest
	if err := guest.engine.MemWrite(stackBase, call.stack); err != nil {
		return 0, err
	}
	if err := deliver(); err != nil {
		return 0, err
	}
	address, err := guest.services.resolve("guest.resume")
	if err != nil {
		return 0, err
	}
	guest.services.entries[address] = shimEntry{name: "guest.resume", handler: func() error {
		if err := guest.engine.RestoreCPU(call.cpu); err != nil {
			return err
		}
		guest.services.callbackReturns = append(guest.services.callbackReturns[:0], call.callbacks...)
		if err := guest.engine.RegWrite(unicorn.RegX0, result); err != nil {
			return err
		}
		return guest.engine.RegWrite(unicorn.RegPC, call.link)
	}}
	return guest.invoke(address)
}
