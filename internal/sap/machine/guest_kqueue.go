package machine

import (
	"encoding/binary"
	"errors"
)

type guestProcessQueue struct {
	closed  bool
	watches map[uint64]uint64
}

type guestKqueues struct {
	guest      *shims
	pid        uint64
	queues     map[uint64]*guestProcessQueue
	operations []map[string]any
}

// Only synthetic guest processes exist here. No host descriptor is allocated,
// watched or closed, and no successful event is invented for a live process.
func installGuestKqueues(guest *shims, pid uint64) (*guestKqueues, error) {
	if pid == 0 || pid > 0x7fffffff {
		return nil, errors.New("invalid guest process ID")
	}
	state := &guestKqueues{guest: guest, pid: pid, queues: map[uint64]*guestProcessQueue{}}
	for name, handler := range map[string]shimHandler{"_kqueue": state.create, "_kevent": state.change} {
		address, err := guest.resolve(name)
		if err != nil {
			return nil, err
		}
		guest.entries[address] = shimEntry{name: name, handler: handler}
	}
	for _, name := range []string{"_close", "_close$UNIX2003"} {
		address, err := guest.resolve(name)
		if err != nil {
			return nil, err
		}
		original := guest.entries[address].handler
		guest.entries[address] = shimEntry{name: name, handler: func() error {
			fd, err := guest.argument(0)
			if err != nil {
				return err
			}
			queue := state.queues[fd]
			if queue == nil {
				return original()
			}
			if queue.closed {
				return state.failure(9)
			}
			queue.closed = true
			clear(queue.watches)
			return guest.setResult(0)
		}}
	}
	return state, nil
}

func (state *guestKqueues) failure(errno uint32) error {
	if err := state.guest.writeUint32(state.guest.errno, errno); err != nil {
		return err
	}
	return state.guest.setResult(^uint64(0))
}

func (state *guestKqueues) create() error {
	if len(state.queues) >= 16 {
		return errors.New("guest event queue limit reached")
	}
	// Other virtual files use descriptors >= 100. Stdio is not open here.
	fd := uint64(len(state.queues))
	state.queues[fd] = &guestProcessQueue{watches: map[uint64]uint64{}}
	return state.guest.setResult(fd)
}

func (state *guestKqueues) change() error {
	var args [6]uint64
	for index := range args {
		value, err := state.guest.argument(index)
		if err != nil {
			return err
		}
		args[index] = value
	}
	fd, pointer, count, output, events, timeout := args[0], args[1], args[2], args[3], args[4], args[5]
	if count > 16 || events > 16 || len(state.operations) >= 64 {
		return errors.New("guest kevent bounds exceeded")
	}
	observation := map[string]any{"queue": fd, "changes": count}
	state.operations = append(state.operations, observation)
	queue := state.queues[fd]
	if queue == nil || queue.closed {
		observation["errno"] = 9
		return state.failure(9)
	}
	if events != 0 {
		if output == 0 || timeout == 0 {
			return errors.New("blocking guest event reads are not modeled")
		}
		data, err := state.guest.engine.MemRead(timeout, 16)
		if err != nil {
			return err
		}
		if binary.LittleEndian.Uint64(data) != 0 || binary.LittleEndian.Uint64(data[8:]) != 0 {
			return errors.New("timed guest event reads are not modeled")
		}
	}
	var changes []struct{ pid, flags, data uint64 }
	if count != 0 {
		data, err := state.guest.engine.MemRead(pointer, count*32)
		if err != nil {
			return err
		}
		for index := uint64(0); index < count; index++ {
			row := data[index*32 : (index+1)*32]
			pid := binary.LittleEndian.Uint64(row)
			filter := int16(binary.LittleEndian.Uint16(row[8:]))
			flags := binary.LittleEndian.Uint16(row[10:])
			note := binary.LittleEndian.Uint32(row[12:])
			if pid != state.pid || filter != -5 || (flags != 1 && flags != 17 && flags != 2) || (note != 0x80000000 && flags != 2) || binary.LittleEndian.Uint64(row[16:]) != 0 {
				return errors.New("unsupported guest process watch")
			}
			changes = append(changes, struct{ pid, flags, data uint64 }{pid, uint64(flags), binary.LittleEndian.Uint64(row[24:])})
			observation["ident"], observation["filter"], observation["flags"], observation["fflags"] = pid, filter, flags, note
		}
	}
	for _, change := range changes {
		if change.flags == 2 {
			if _, exists := queue.watches[change.pid]; !exists {
				observation["errno"] = 2
				return state.failure(2)
			}
			delete(queue.watches, change.pid)
		} else {
			queue.watches[change.pid] = change.data
		}
	}
	observation["watched_processes"] = len(queue.watches)
	observation["events_returned"] = 0
	return state.guest.setResult(0)
}
