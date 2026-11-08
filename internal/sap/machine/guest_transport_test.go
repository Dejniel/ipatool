package machine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestGuestKqueueRegistersOnlyGuestProcesses(t *testing.T) {
	guest := newServiceTestMachine(t)
	queues, err := installGuestKqueues(guest.services, 501)
	if err != nil {
		t.Fatal(err)
	}
	if result := guestCFCall(t, guest, "_kevent", 0, 0, 0, 0, 0, 0); int64(result) != -1 {
		t.Fatal("absent queue accepted")
	}
	fd := guestCFCall(t, guest, "_kqueue")
	change := make([]byte, 32)
	binary.LittleEndian.PutUint64(change, 501)
	binary.LittleEndian.PutUint16(change[8:], 0xfffb)
	binary.LittleEndian.PutUint16(change[10:], 17)
	binary.LittleEndian.PutUint32(change[12:], 0x80000000)
	if err := guest.engine.MemWrite(scratchBase, change); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_kevent", fd, scratchBase, 1, 0, 0, 0); got != 0 || len(queues.queues[fd].watches) != 1 {
		t.Fatal("process watch not registered")
	}
	if got := guestCFCall(t, guest, "_kevent", fd, 0, 0, scratchBase+256, 1, scratchBase+128); got != 0 {
		t.Fatal("live process produced an invented exit event")
	}
	binary.LittleEndian.PutUint64(change, 777)
	if err := guest.engine.MemWrite(scratchBase, change); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_kevent"], fd, scratchBase, 1, 0, 0, 0); err == nil {
		t.Fatal("unregistered process accepted")
	}
	guestCFCall(t, guest, "_close", fd)
	if got := guestCFCall(t, guest, "_kevent", fd, 0, 0, 0, 0, 0); int64(got) != -1 || len(queues.queues[fd].watches) != 0 {
		t.Fatal("closed queue retained a live watch")
	}
}

func TestGuestMachReplyTransfersOwnedBuffer(t *testing.T) {
	guest := newServiceTestMachine(t)
	data := []byte("test OOL payload")
	address, err := guest.services.allocate(uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(address, data); err != nil {
		t.Fatal(err)
	}
	sent := make([]byte, 72)
	binary.LittleEndian.PutUint32(sent, 0x80000012)
	binary.LittleEndian.PutUint32(sent[4:], uint32(len(sent)))
	binary.LittleEndian.PutUint32(sent[8:], 0x2100)
	binary.LittleEndian.PutUint32(sent[20:], 1302)
	binary.LittleEndian.PutUint32(sent[24:], 1)
	binary.LittleEndian.PutUint64(sent[28:], address)
	sent[36], sent[37], sent[39] = 1, 1, 1
	binary.LittleEndian.PutUint32(sent[40:], uint32(len(data)))
	received, owned, err := receiveGuestMachReply(guest.services, sent, 0x2100, func(uint32) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 80 || binary.LittleEndian.Uint32(received[8:]) != 0 || binary.LittleEndian.Uint32(received[12:]) != 0x2100 {
		t.Fatal("reply header or trailer was not translated")
	}
	destination := binary.LittleEndian.Uint64(received[28:])
	got, err := guest.engine.MemRead(destination, uint64(len(data)))
	if err != nil || !bytes.Equal(got, data) || destination == address || owned[destination] != uint64(len(data)) {
		t.Fatal("out-of-line ownership not transferred")
	}
	if _, exists := guest.services.allocations[address]; exists {
		t.Fatal("sender's transferred buffer was retained")
	}
	sent[0] = 0
	if _, _, err := receiveGuestMachReply(guest.services, sent, 0x2100, func(uint32) bool { return true }); err == nil {
		t.Fatal("unknown reply disposition accepted")
	}
}

func TestGuestResumeRestoresOverwrittenClientStack(t *testing.T) {
	guest := newServiceTestMachine(t)
	pause := errors.New("synthetic transport pause")
	address, err := guest.services.addFunction("guest.pause", func() error { return pause })
	if err != nil {
		t.Fatal(err)
	}
	// Save LR; set x19; call the transport; add its return to x19; restore LR.
	words := []uint32{0xa9bf7bfd, 0x910003fd, 0xd2800233, 0x580001b0, 0xd63f0200, 0x8b130000, 0xa8c17bfd, 0xd65f03c0}
	code := make([]byte, 72)
	for index, word := range words {
		binary.LittleEndian.PutUint32(code[index*4:], word)
	}
	binary.LittleEndian.PutUint64(code[64:], address)
	if err := guest.engine.MemWrite(scratchBase, code); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(scratchBase); !errors.Is(err, pause) {
		t.Fatalf("synthetic transport did not suspend: %v", err)
	}
	call, err := suspendGuestCall(guest)
	if err != nil {
		t.Fatal(err)
	}
	defer call.clear()
	frame, err := guest.engine.MemRead(stackEnd-16, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(stackEnd-16, bytes.Repeat([]byte{0xcc}, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_malloc"], 32); err != nil {
		t.Fatal(err)
	}
	result, err := call.resumeAfterReturn(5, func() error { return nil })
	if err != nil || result != 22 {
		t.Fatalf("resumed call lost its register/frame state: result=%d error=%v", result, err)
	}
	got, err := guest.engine.MemRead(stackEnd-16, 16)
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatal("client stack was not restored")
	}
	if _, err := call.resumeAfterReturn(0, func() error { return nil }); err == nil {
		t.Fatal("suspended call resumed twice")
	}
}
