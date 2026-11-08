package machine

import "errors"

type guestMachService struct {
	port      uint32
	checkedIn bool
}

type guestBootstrap struct {
	services map[string]*guestMachService
}

func installGuestBootstrap(guest *shims, names []string) (*guestBootstrap, error) {
	state := &guestBootstrap{services: map[string]*guestMachService{}}
	if len(names) > 16 {
		return nil, errors.New("guest bootstrap service limit reached")
	}
	for index, name := range names {
		if len(name) == 0 || len(name) >= 128 || state.services[name] != nil {
			return nil, errors.New("invalid guest bootstrap reservation")
		}
		state.services[name] = &guestMachService{port: uint32(0x2000 + index)}
	}
	for _, operation := range []string{"_bootstrap_look_up", "_bootstrap_check_in"} {
		address, err := guest.resolve(operation)
		if err != nil {
			return nil, err
		}
		guest.entries[address] = shimEntry{name: operation, handler: func() error {
			namePointer, err := guest.argument(1)
			if err != nil {
				return err
			}
			name, err := guest.readCString(namePointer)
			if err != nil {
				return err
			}
			if len(name) == 0 || len(name) >= 128 {
				return errors.New("invalid guest bootstrap service name")
			}
			output, err := guest.argument(2)
			if err != nil {
				return err
			}
			if output == 0 {
				return errors.New("guest bootstrap port output is null")
			}
			service := state.services[name]
			status := uint64(1102) // BOOTSTRAP_UNKNOWN_SERVICE
			var port uint32
			if service != nil {
				status = 0
				port = service.port
				if operation == "_bootstrap_check_in" {
					if service.checkedIn {
						status = 1103 // BOOTSTRAP_SERVICE_ACTIVE
						port = 0
					}
				}
			}
			if err := guest.writeUint32(output, port); err != nil {
				return err
			}
			if status == 0 && operation == "_bootstrap_check_in" {
				service.checkedIn = true
			}
			return guest.setResult(status)
		}}
	}
	return state, nil
}
