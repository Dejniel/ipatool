package machine

import (
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf16"

	"howett.net/plist"
)

func (state *guestCFURLs) streamObject() (*guestCFObject, error) {
	address, err := state.guest.argument(0)
	if err != nil {
		return nil, err
	}
	object, ok := state.objects[address]
	if !ok || object.kind != guestCFStreamType || object.refs == 0 {
		return nil, errors.New("unknown, released or incorrectly typed guest CF stream")
	}
	return object, nil
}

func (state *guestCFURLs) createReadStream() error {
	address, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	object, ok := state.objects[address]
	if !ok || object.kind != guestCFURLType || object.refs == 0 {
		return errors.New("guest CF stream requires a live file URL")
	}
	stream, err := state.newObject(guestCFStreamType, object.text, false)
	if err != nil {
		return err
	}
	return state.guest.setResult(stream)
}

func (state *guestCFURLs) openReadStream() error {
	stream, err := state.streamObject()
	if err != nil {
		return err
	}
	if stream.opened {
		return errors.New("guest CF stream is already open")
	}
	if stream.closed {
		return state.guest.setResult(0)
	}
	data, exists := state.files[stream.text]
	if !exists {
		return state.guest.setResult(0)
	}
	stream.data, stream.opened, stream.position = data, true, 0
	return state.guest.setResult(1)
}

func (state *guestCFURLs) readStream() error {
	stream, err := state.streamObject()
	if err != nil {
		return err
	}
	pointer, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	capacity, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	if !stream.opened || int64(capacity) < 0 || pointer == 0 && capacity != 0 {
		return state.guest.setResult(math.MaxUint64)
	}
	count := min(capacity, uint64(len(stream.data)-stream.position))
	if count != 0 {
		if err := state.guest.engine.MemWrite(pointer, stream.data[stream.position:stream.position+int(count)]); err != nil {
			return err
		}
	}
	stream.position += int(count)
	return state.guest.setResult(count)
}

func (state *guestCFURLs) closeReadStream() error {
	stream, err := state.streamObject()
	if err != nil {
		return err
	}
	stream.opened = false
	stream.closed = true
	return state.guest.setResult(0)
}

func (state *guestCFURLs) propertyListFromStream() error {
	var arguments [6]uint64
	for index := range arguments {
		value, err := state.guest.argument(index)
		if err != nil {
			return err
		}
		arguments[index] = value
	}
	stream, ok := state.objects[arguments[1]]
	if !ok || stream.kind != guestCFStreamType || stream.refs == 0 || !stream.opened {
		return errors.New("guest plist requires an open guest CF stream")
	}
	if arguments[3] != 0 || int64(arguments[2]) < 0 {
		return errors.New("unsupported guest plist options or stream length")
	}
	data := stream.data[stream.position:]
	if arguments[2] != 0 && arguments[2] < uint64(len(data)) {
		data = data[:arguments[2]]
	}
	var values map[string]any
	format, err := plist.Unmarshal(data, &values)
	if err != nil {
		return errors.New("guest guest plist cannot be decoded")
	}
	var nativeFormat uint64
	switch format {
	case plist.XMLFormat:
		nativeFormat = 100
	case plist.BinaryFormat:
		nativeFormat = 200
	default:
		return errors.New("unsupported guest plist format")
	}
	for _, value := range values {
		if _, ok := value.(string); !ok {
			return errors.New("guest guest plist only supports string-valued dictionaries")
		}
	}
	if len(values)+1 > guestMaxCFObjects-len(state.objects) {
		return errors.New("guest plist object limit reached")
	}
	address, err := state.newObject(guestCFDictType, "", false)
	if err != nil {
		return err
	}
	dictionary := state.objects[address]
	dictionary.values = map[string]uint64{}
	for key, value := range values {
		child, err := state.newObject(guestCFStringType, value.(string), false)
		if err != nil {
			return err
		}
		dictionary.values[key] = child
		dictionary.owned = append(dictionary.owned, child)
	}
	if arguments[4] != 0 {
		if err := state.guest.writeUint64(arguments[4], nativeFormat); err != nil {
			return err
		}
	}
	if arguments[5] != 0 {
		if err := state.guest.writeUint64(arguments[5], 0); err != nil {
			return err
		}
	}
	stream.position += len(data)
	return state.guest.setResult(address)
}

func (state *guestCFURLs) constantString(address uint64) (string, error) {
	if object, ok := state.objects[address]; ok {
		if object.kind != guestCFStringType || object.refs == 0 {
			return "", errors.New("invalid guest CF string key")
		}
		return object.text, nil
	}
	data, err := state.guest.engine.MemRead(address, 32)
	if err != nil {
		return "", err
	}
	flags := binary.LittleEndian.Uint64(data[8:16]) & 0xffff
	if flags != 0x7c8 && flags != 0x7d0 {
		return "", errors.New("unsupported guest constant CF string layout")
	}
	pointer, length := binary.LittleEndian.Uint64(data[16:24]), binary.LittleEndian.Uint64(data[24:32])
	if pointer == 0 || length > guestMaxPathBytes {
		return "", errors.New("invalid guest constant CF string extent")
	}
	width := uint64(1)
	if flags == 0x7d0 {
		width = 2
	}
	value, err := state.guest.engine.MemRead(pointer, length*width)
	if err != nil {
		return "", err
	}
	if width == 1 {
		return string(value), nil
	}
	units := make([]uint16, length)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(value[2*index:])
	}
	return string(utf16.Decode(units)), nil
}

func (state *guestCFURLs) dictionaryValue(object *guestCFObject, _ uint64) error {
	if object.kind != guestCFDictType {
		return errors.New("guest CF dictionary has incorrect type")
	}
	pointer, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	key, err := state.constantString(pointer)
	if err != nil {
		return err
	}
	if len(state.keys) >= guestMaxCFObjects {
		return errors.New("guest CF dictionary lookup limit reached")
	}
	state.keys = append(state.keys, key)
	return state.guest.setResult(object.values[key])
}
