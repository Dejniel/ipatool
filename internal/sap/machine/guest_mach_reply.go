package machine

import (
	"encoding/binary"
	"errors"
)

// Translate only the captured server reply contract: a send-once destination,
// no reply port, bounded OOL buffers and send rights to registered guest ports.
func receiveGuestMachReply(guest *shims, sent []byte, replyPort uint32, knownPort func(uint32) bool) ([]byte, map[uint64]uint64, error) {
	if len(sent) < 24 || len(sent) > 1<<20 || binary.LittleEndian.Uint32(sent[4:]) != uint32(len(sent)) || binary.LittleEndian.Uint32(sent[8:]) != replyPort || binary.LittleEndian.Uint32(sent[12:]) != 0 {
		return nil, nil, errors.New("unexpected guest Mach reply header")
	}
	bits := binary.LittleEndian.Uint32(sent)
	if bits&0x7fffffff != 18 {
		return nil, nil, errors.New("unexpected guest reply port dispositions")
	}
	received := make([]byte, len(sent)+8)
	copy(received, sent)
	binary.LittleEndian.PutUint32(received, bits&0x80000000|0x1000)
	binary.LittleEndian.PutUint32(received[8:], 0)
	binary.LittleEndian.PutUint32(received[12:], replyPort)
	binary.LittleEndian.PutUint32(received[len(sent)+4:], 8)
	owned, err := relocateGuestMachDescriptors(guest, received[:len(sent)], knownPort)
	return received, owned, err
}

func receiveGuestMachRequest(guest *shims, sent []byte, knownPort func(uint32) bool) ([]byte, map[uint64]uint64, error) {
	if len(sent) < 24 || len(sent) > 1<<20 || !knownPort(binary.LittleEndian.Uint32(sent[8:])) {
		return nil, nil, errors.New("unexpected guest Mach request header")
	}
	bits := binary.LittleEndian.Uint32(sent)
	if bits&0x7fffffff != 0x1513 {
		return nil, nil, errors.New("unsupported guest request dispositions")
	}
	received := make([]byte, len(sent)+52)
	copy(received, sent)
	binary.LittleEndian.PutUint32(received, bits&0x80000000|0x1012)
	binary.LittleEndian.PutUint32(received[4:], uint32(len(sent)))
	binary.LittleEndian.PutUint32(received[8:], binary.LittleEndian.Uint32(sent[12:]))
	binary.LittleEndian.PutUint32(received[12:], binary.LittleEndian.Uint32(sent[8:]))
	binary.LittleEndian.PutUint32(received[len(sent)+4:], 52)
	binary.LittleEndian.PutUint32(received[len(sent)+12:], 501)
	binary.LittleEndian.PutUint32(received[len(sent)+16:], 20)
	for index, value := range []uint32{501, 501, 20, 501, 20, 501, 0, 0} {
		binary.LittleEndian.PutUint32(received[len(sent)+20+index*4:], value)
	}
	owned, err := relocateGuestMachDescriptors(guest, received[:len(sent)], knownPort)
	return received, owned, err
}

func relocateGuestMachDescriptors(guest *shims, sent []byte, knownPort func(uint32) bool) (map[uint64]uint64, error) {
	owned := map[uint64]uint64{}
	bits := binary.LittleEndian.Uint32(sent)
	if bits&0x80000000 == 0 {
		return owned, nil
	}
	if len(sent) < 28 {
		return nil, errors.New("truncated guest descriptor count")
	}
	count := binary.LittleEndian.Uint32(sent[24:])
	if count == 0 || count > 8 {
		return nil, errors.New("guest reply descriptor limit exceeded")
	}
	position := 28
	for index := uint32(0); index < count; index++ {
		if len(sent)-position < 12 {
			return nil, errors.New("truncated guest Mach descriptor")
		}
		switch sent[position+11] {
		case 0:
			port := binary.LittleEndian.Uint32(sent[position:])
			disposition := sent[position+10]
			if !knownPort(port) || (disposition != 17 && disposition != 19 && disposition != 20) {
				return nil, errors.New("unknown guest reply send right")
			}
			sent[position+10] = 17
			position += 12
		case 1:
			if len(sent)-position < 16 {
				return nil, errors.New("truncated guest OOL descriptor")
			}
			address := binary.LittleEndian.Uint64(sent[position:])
			size := uint64(binary.LittleEndian.Uint32(sent[position+12:]))
			if size == 0 || size > 1<<20 || sent[position+8] > 1 || sent[position+9] != 1 {
				return nil, errors.New("unsupported guest reply OOL extent")
			}
			allocation, exists := guest.allocations[address]
			if sent[position+8] == 1 && (!exists || allocation.size < size) {
				return nil, errors.New("unowned guest reply buffer")
			}
			data, err := guest.engine.MemRead(address, size)
			if err != nil {
				return nil, err
			}
			destination, err := guest.allocate(size)
			if err != nil {
				return nil, err
			}
			if err := guest.engine.MemWrite(destination, data); err != nil {
				return nil, err
			}
			binary.LittleEndian.PutUint64(sent[position:], destination)
			owned[destination] = size
			if sent[position+8] == 1 {
				if err := guest.release(address); err != nil {
					return nil, err
				}
			}
			position += 16
		default:
			return nil, errors.New("unsupported guest reply descriptor type")
		}
	}
	return owned, nil
}
