package machine

import "errors"

// This guest has an IOKit namespace, but no hardware providers. Matching is
// real dictionary/iterator bookkeeping, never host IOKit or a fabricated device.
type guestIOKit struct {
	cf        *guestCFURLs
	queries   []string
	iterators map[uint64]bool
	next      uint64
}

func installGuestIOKit(cf *guestCFURLs) (*guestIOKit, error) {
	state := &guestIOKit{cf: cf, iterators: map[uint64]bool{}, next: 0x4000}
	for name, handler := range map[string]shimHandler{
		"_IOMainPort":                   state.mainPort,
		"_IOServiceMatching":            state.matching,
		"_IOServiceGetMatchingServices": state.getMatching,
		"_IOIteratorNext":               state.nextObject,
		"_IOObjectRelease":              state.release,
	} {
		if err := cf.replace(name, handler); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (state *guestIOKit) mainPort() error {
	output, err := state.cf.guest.argument(1)
	if err != nil {
		return err
	}
	if err := state.cf.guest.writeUint32(output, 0x3000); err != nil {
		return err
	}
	return state.cf.guest.setResult(0)
}

func (state *guestIOKit) matching() error {
	pointer, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	name, err := state.cf.guest.readCString(pointer)
	if err != nil {
		return err
	}
	if name == "" || len(name) > 256 || len(state.queries) >= 16 {
		return errors.New("invalid or excessive guest IOKit matching")
	}
	value, err := state.cf.newObject(guestCFStringType, name, false)
	if err != nil {
		return err
	}
	matching, err := state.cf.newObject(guestCFDictType, "", false)
	if err != nil {
		return err
	}
	state.cf.objects[matching].values = map[string]uint64{"IOProviderClass": value}
	state.cf.objects[matching].owned = []uint64{value}
	state.queries = append(state.queries, name)
	return state.cf.guest.setResult(matching)
}

func (state *guestIOKit) getMatching() error {
	port, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	matching, err := state.cf.guest.argument(1)
	if err != nil {
		return err
	}
	output, err := state.cf.guest.argument(2)
	if err != nil {
		return err
	}
	object := state.cf.objects[matching]
	if port != 0x3000 || object == nil || object.kind != guestCFDictType || object.refs == 0 || len(state.iterators) >= 16 {
		return errors.New("unknown guest IOKit port or matching dictionary")
	}
	iterator := state.next
	if err := state.cf.guest.writeUint32(output, uint32(iterator)); err != nil {
		return err
	}
	state.next++
	state.iterators[iterator] = true
	if err := state.cf.releaseObject(object); err != nil {
		return err
	}
	return state.cf.guest.setResult(0)
}

func (state *guestIOKit) nextObject() error {
	iterator, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	if !state.iterators[iterator] {
		return errors.New("unknown guest IOKit iterator")
	}
	return state.cf.guest.setResult(0)
}

func (state *guestIOKit) release() error {
	iterator, err := state.cf.guest.argument(0)
	if err != nil {
		return err
	}
	if !state.iterators[iterator] {
		return errors.New("unknown guest IOKit release")
	}
	delete(state.iterators, iterator)
	return state.cf.guest.setResult(0)
}
