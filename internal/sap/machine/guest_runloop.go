package machine

import (
	"errors"
	"math"
)

const (
	guestCFMachPortType = 0x10005
	guestCFSourceType   = 0x10006
	guestCFLoopType     = 0x10007
)

var errGuestRunLoopReady = errors.New("isolated service reached its event loop; message dispatch is not implemented")

type guestMachCallback struct {
	port     uint64
	callback uint64
	info     uint64
}

type guestRunLoop struct {
	cf      *guestCFURLs
	ports   map[uint64]guestMachCallback
	sources map[uint64]uint64
	active  map[uint64]bool
	invalid map[uint64]bool
	loop    uint64
	mode    uint64
	waiting bool
}

func installGuestRunLoop(cf *guestCFURLs) (*guestRunLoop, error) {
	state := &guestRunLoop{cf: cf, ports: map[uint64]guestMachCallback{}, sources: map[uint64]uint64{}, active: map[uint64]bool{}, invalid: map[uint64]bool{}}
	var err error
	state.mode, err = cf.newObject(guestCFStringType, "kCFRunLoopDefaultMode", false)
	if err != nil {
		return nil, err
	}
	modeSymbol, err := cf.guest.resolve("_kCFRunLoopDefaultMode")
	if err != nil {
		return nil, err
	}
	if err := cf.guest.writeUint64(modeSymbol, state.mode); err != nil {
		return nil, err
	}
	for name, handler := range map[string]shimHandler{
		"_CFMachPortCreate":              state.createNewPort,
		"_CFMachPortCreateWithPort":      state.createPort,
		"_CFMachPortCreateRunLoopSource": state.createSource,
		"_CFMachPortGetPort":             state.getPort,
		"_CFMachPortInvalidate":          state.invalidatePort,
		"_CFRunLoopGetMain":              state.getMain,
		"_CFRunLoopAddSource":            state.addSource,
		"_CFRunLoopRun":                  state.run,
	} {
		if err := cf.replace(name, handler); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (state *guestRunLoop) createPort() error {
	guest := state.cf.guest
	port, err := guest.argument(1)
	if err != nil {
		return err
	}
	callback, err := guest.argument(2)
	if err != nil {
		return err
	}
	context, err := guest.argument(3)
	if err != nil {
		return err
	}
	shouldFree, err := guest.argument(4)
	if err != nil {
		return err
	}
	return state.registerPort(port, callback, context, shouldFree)
}

func (state *guestRunLoop) createNewPort() error {
	guest := state.cf.guest
	callback, err := guest.argument(1)
	if err != nil {
		return err
	}
	context, err := guest.argument(2)
	if err != nil {
		return err
	}
	shouldFree, err := guest.argument(3)
	if err != nil {
		return err
	}
	return state.registerPort(0x5000+uint64(len(state.ports)), callback, context, shouldFree)
}

func (state *guestRunLoop) registerPort(port, callback, context, shouldFree uint64) error {
	guest := state.cf.guest
	if port == 0 || port > math.MaxUint32 || callback == 0 || len(state.ports) >= 16 {
		return errors.New("invalid or excessive guest Mach port callbacks")
	}
	for _, existing := range state.ports {
		if existing.port == port {
			return errors.New("duplicate guest Mach port registration is unsupported")
		}
	}
	var info uint64
	if context != 0 {
		for index := uint64(0); index < 5; index++ {
			value, err := guest.readUint64(context + index*8)
			if err != nil {
				return err
			}
			if index == 1 {
				info = value
			} else if value != 0 {
				return errors.New("unsupported guest Mach port context callbacks or version")
			}
		}
	}
	if shouldFree != 0 {
		if err := guest.engine.MemWrite(shouldFree, []byte{0}); err != nil {
			return err
		}
	}
	handle, err := state.cf.newObject(guestCFMachPortType, "", false)
	if err != nil {
		return err
	}
	state.ports[handle] = guestMachCallback{port: port, callback: callback, info: info}
	return guest.setResult(handle)
}

func (state *guestRunLoop) createSource() error {
	port, err := state.cf.guest.argument(1)
	if err != nil {
		return err
	}
	object := state.cf.objects[port]
	if object == nil || object.kind != guestCFMachPortType || object.refs == 0 || state.invalid[port] {
		return errors.New("unknown guest Mach port")
	}
	handle, err := state.cf.newObject(guestCFSourceType, "", false)
	if err != nil {
		return err
	}
	object.refs++
	state.cf.objects[handle].owned = []uint64{port}
	state.sources[handle] = port
	return state.cf.guest.setResult(handle)
}

func (state *guestRunLoop) invalidatePort() error {
	handle, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	object := state.cf.objects[handle]
	if object == nil || object.kind != guestCFMachPortType || object.refs == 0 {
		return errors.New("unknown or released guest Mach port")
	}
	state.invalid[handle] = true
	for source, port := range state.sources {
		if port == handle && state.active[source] {
			delete(state.active, source)
			if loop := state.cf.objects[state.loop]; loop != nil {
				for index, owned := range loop.owned {
					if owned == source {
						loop.owned = append(loop.owned[:index], loop.owned[index+1:]...)
						break
					}
				}
			}
			if err := state.cf.releaseObject(state.cf.objects[source]); err != nil {
				return err
			}
		}
	}
	return state.cf.guest.setResult(0)
}

func (state *guestRunLoop) getPort() error {
	handle, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	object := state.cf.objects[handle]
	value, exists := state.ports[handle]
	if !exists || object.refs == 0 {
		return errors.New("unknown or released guest Mach port")
	}
	return state.cf.guest.setResult(value.port)
}

func (state *guestRunLoop) getMain() error {
	if state.loop == 0 {
		var err error
		state.loop, err = state.cf.newObject(guestCFLoopType, "", false)
		if err != nil {
			return err
		}
	}
	return state.cf.guest.setResult(state.loop)
}

func (state *guestRunLoop) addSource() error {
	loop, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	source, err := state.cf.guest.argument(1)
	if err != nil {
		return err
	}
	mode, err := state.cf.guest.argument(2)
	if err != nil {
		return err
	}
	object := state.cf.objects[source]
	if loop == 0 || loop != state.loop || object == nil || object.kind != guestCFSourceType || object.refs == 0 || mode != state.mode || state.invalid[state.sources[source]] {
		return errors.New("unknown guest run-loop source, loop or mode")
	}
	if !state.active[source] {
		object.refs++
		state.cf.objects[loop].owned = append(state.cf.objects[loop].owned, source)
		state.active[source] = true
	}
	return state.cf.guest.setResult(0)
}

func (state *guestRunLoop) run() error {
	if len(state.active) == 0 {
		return errors.New("guest run loop has no scheduled sources")
	}
	state.waiting = true
	return errGuestRunLoopReady
}
