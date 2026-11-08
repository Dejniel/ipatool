package machine

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	guestMaxCFObjects = 256
	guestMaxPathBytes = 4096
	guestCFURLType    = 0x10001
	guestCFStringType = 0x10002
	guestCFStreamType = 0x10003
	guestCFDictType   = 0x10004
	guestUTF8         = 0x08000100
)

type guestCFObject struct {
	kind      uint64
	text      string
	directory bool
	refs      uint64
	owned     []uint64
	stringRef uint64
	values    map[string]uint64
	data      []byte
	opened    bool
	closed    bool
	position  int
}

// These opaque objects exist only in the guest. No operation opens a host path.
type guestCFURLs struct {
	guest   *shims
	objects map[uint64]*guestCFObject
	paths   []string
	files   map[string][]byte
	keys    []string
}

func installGuestCFURL(guest *shims, files map[string][]byte) (*guestCFURLs, error) {
	state := &guestCFURLs{guest: guest, objects: map[uint64]*guestCFObject{}, files: map[string][]byte{}}
	if len(files) > 16 {
		return nil, errors.New("guest CF file limit reached")
	}
	total := 0
	for name, data := range files {
		total += len(data)
		if !path.IsAbs(name) || path.Clean(name) != name || total > 1<<20 {
			return nil, errors.New("invalid or oversized guest CF files")
		}
		state.files[name] = bytes.Clone(data)
	}
	for name, handler := range map[string]shimHandler{
		"_CFURLCreateFromFileSystemRepresentation": state.createURL,
		"_CFURLGetFileSystemRepresentation":        state.fileSystemRepresentation,
		"_CFURLCopyFileSystemPath":                 state.copyFileSystemPath,
		"_CFURLGetString":                          state.getURLString,
		"_CFURLHasDirectoryPath":                   state.hasDirectoryPath,
		"_CFURLGetTypeID":                          func() error { return guest.setResult(guestCFURLType) },
		"_CFStringGetTypeID":                       func() error { return guest.setResult(guestCFStringType) },
		"_CFDictionaryGetTypeID":                   func() error { return guest.setResult(guestCFDictType) },
		"_CFReadStreamCreateWithFile":              state.createReadStream,
		"_CFReadStreamOpen":                        state.openReadStream,
		"_CFReadStreamRead":                        state.readStream,
		"_CFReadStreamClose":                       state.closeReadStream,
		"_CFPropertyListCreateWithStream":          state.propertyListFromStream,
	} {
		if err := state.replace(name, handler); err != nil {
			return nil, err
		}
	}
	for name, handler := range map[string]func(*guestCFObject, uint64) error{
		"_CFRetain": func(object *guestCFObject, address uint64) error {
			if object.refs == math.MaxUint64 {
				return errors.New("guest CF reference overflow")
			}
			object.refs++
			return guest.setResult(address)
		},
		"_CFRelease": func(object *guestCFObject, _ uint64) error {
			if err := state.releaseObject(object); err != nil {
				return err
			}
			return guest.setResult(0)
		},
		"_CFGetTypeID": func(object *guestCFObject, _ uint64) error { return guest.setResult(object.kind) },
		"_CFStringGetLength": func(object *guestCFObject, _ uint64) error {
			if object.kind != guestCFStringType {
				return errors.New("guest CF string has incorrect type")
			}
			return guest.setResult(uint64(len(utf16.Encode([]rune(object.text)))))
		},
		"_CFStringGetCString":    state.stringCString,
		"_CFStringGetCStringPtr": state.stringCStringPointer,
		"_CFDictionaryGetValue":  state.dictionaryValue,
	} {
		address, err := guest.resolve(name)
		if err != nil {
			return nil, err
		}
		original := guest.entries[address].handler
		if err := state.replace(name, func() error {
			pointer, err := guest.argument(0)
			if err != nil {
				return err
			}
			object, managed := state.objects[pointer]
			if !managed {
				return original()
			}
			if object.refs == 0 {
				return errors.New("guest CF object has been released")
			}
			return handler(object, pointer)
		}); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (state *guestCFURLs) releaseObject(object *guestCFObject) error {
	if object == nil || object.refs == 0 {
		return errors.New("guest CF object ownership is invalid")
	}
	object.refs--
	if object.refs == 0 {
		for _, address := range object.owned {
			if err := state.releaseObject(state.objects[address]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *guestCFURLs) replace(name string, handler shimHandler) error {
	address, err := state.guest.resolve(name)
	if err != nil {
		return err
	}
	state.guest.entries[address] = shimEntry{name: name, handler: handler}
	return nil
}

func (state *guestCFURLs) newObject(kind uint64, text string, directory bool) (uint64, error) {
	if len(state.objects) >= guestMaxCFObjects {
		return 0, errors.New("guest CF object limit reached")
	}
	if len(text) > guestMaxPathBytes*3+16 {
		return 0, errors.New("guest CF object text exceeds limit")
	}
	size := uint64(16)
	if kind == guestCFStringType {
		size += uint64(len(text)) + 1
	}
	address, err := state.guest.allocate(size)
	if err != nil {
		return 0, err
	}
	if kind == guestCFStringType {
		if err := state.guest.engine.MemWrite(address+16, append([]byte(text), 0)); err != nil {
			return 0, err
		}
	}
	state.objects[address] = &guestCFObject{kind: kind, text: text, directory: directory, refs: 1}
	return address, nil
}

func (state *guestCFURLs) stringCStringPointer(object *guestCFObject, address uint64) error {
	if object.kind != guestCFStringType {
		return errors.New("guest CF string has incorrect type")
	}
	encoding, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	if encoding != guestUTF8 {
		return state.guest.setResult(0)
	}
	return state.guest.setResult(address + 16)
}

func (state *guestCFURLs) urlObject() (*guestCFObject, error) {
	address, err := state.guest.argument(0)
	if err != nil {
		return nil, err
	}
	object, ok := state.objects[address]
	if !ok || object.kind != guestCFURLType || object.refs == 0 {
		return nil, errors.New("unknown, released or incorrectly typed guest CFURL")
	}
	return object, nil
}

func (state *guestCFURLs) createURL() error {
	guest := state.guest
	pointer, err := guest.argument(1)
	if err != nil {
		return err
	}
	length, err := guest.argument(2)
	if err != nil {
		return err
	}
	directory, err := guest.argument(3)
	if err != nil {
		return err
	}
	if pointer == 0 || length == 0 || length > guestMaxPathBytes {
		return guest.setResult(0)
	}
	data, err := guest.engine.MemRead(pointer, length)
	if err != nil {
		return err
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return guest.setResult(0)
	}
	if !utf8.Valid(data) || !path.IsAbs(string(data)) {
		return errors.New("guest CFURL requires an absolute UTF-8 guest path")
	}
	value := path.Clean(string(data))
	address, err := state.newObject(guestCFURLType, value, directory != 0)
	if err != nil {
		return err
	}
	state.paths = append(state.paths, value)
	return guest.setResult(address)
}

func (state *guestCFURLs) writeCString(text string, pointer, capacity uint64) error {
	if pointer == 0 || int64(capacity) <= 0 || uint64(len(text))+1 > capacity {
		return state.guest.setResult(0)
	}
	if err := state.guest.engine.MemWrite(pointer, append([]byte(text), 0)); err != nil {
		return err
	}
	return state.guest.setResult(1)
}

func (state *guestCFURLs) fileSystemRepresentation() error {
	object, err := state.urlObject()
	if err != nil {
		return err
	}
	pointer, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	capacity, err := state.guest.argument(3)
	if err != nil {
		return err
	}
	return state.writeCString(object.text, pointer, capacity)
}

func (state *guestCFURLs) copyFileSystemPath() error {
	object, err := state.urlObject()
	if err != nil {
		return err
	}
	style, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	if style != 0 {
		return errors.New("guest CFURL only supports POSIX path style")
	}
	address, err := state.newObject(guestCFStringType, object.text, false)
	if err != nil {
		return err
	}
	return state.guest.setResult(address)
}

func (state *guestCFURLs) getURLString() error {
	object, err := state.urlObject()
	if err != nil {
		return err
	}
	if object.stringRef != 0 {
		return state.guest.setResult(object.stringRef)
	}
	value := (&url.URL{Scheme: "file", Path: object.text}).String()
	if object.directory && !strings.HasSuffix(value, "/") {
		value += "/"
	}
	address, err := state.newObject(guestCFStringType, value, false)
	if err != nil {
		return err
	}
	object.stringRef = address
	object.owned = append(object.owned, address)
	return state.guest.setResult(address)
}

func (state *guestCFURLs) hasDirectoryPath() error {
	object, err := state.urlObject()
	if err != nil {
		return err
	}
	var result uint64
	if object.directory {
		result = 1
	}
	return state.guest.setResult(result)
}

func (state *guestCFURLs) stringCString(object *guestCFObject, _ uint64) error {
	if object.kind != guestCFStringType {
		return errors.New("guest CF string has incorrect type")
	}
	pointer, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	capacity, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	encoding, err := state.guest.argument(3)
	if err != nil {
		return err
	}
	if encoding != guestUTF8 {
		return fmt.Errorf("unsupported guest CF string encoding %#x", encoding)
	}
	return state.writeCString(object.text, pointer, capacity)
}
