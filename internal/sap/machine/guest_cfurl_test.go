package machine

import (
	"bytes"
	"math"
	"testing"
	"unicode/utf16"
)

func guestCFCall(t *testing.T, guest *Machine, name string, arguments ...uint64) uint64 {
	t.Helper()
	value, err := guest.invoke(guest.services.symbols[name], arguments...)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func guestURL(t *testing.T, guest *Machine, value string, directory bool) uint64 {
	t.Helper()
	if err := guest.engine.MemWrite(scratchBase, []byte(value)); err != nil {
		t.Fatal(err)
	}
	var flag uint64
	if directory {
		flag = 1
	}
	return guestCFCall(t, guest, "_CFURLCreateFromFileSystemRepresentation", 0, scratchBase, uint64(len(value)), flag)
}

func TestGuestCFURLRoundTripAndLifetime(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	value := "/guest/a %20#\U00010000"
	url := guestURL(t, guest, value, true)
	if url == 0 || state.objects[url].text != value {
		t.Fatal("URL path changed")
	}
	if guestCFCall(t, guest, "_CFURLHasDirectoryPath", url) != 1 {
		t.Fatal("directory flag lost")
	}
	const buffer = scratchBase + 0x2000
	if guestCFCall(t, guest, "_CFURLGetFileSystemRepresentation", url, 1, buffer, uint64(len(value)+1)) != 1 {
		t.Fatal("path copy failed")
	}
	data, err := guest.engine.MemRead(buffer, uint64(len(value)+1))
	if err != nil || !bytes.Equal(data, append([]byte(value), 0)) {
		t.Fatal("filesystem representation differs")
	}
	stringRef := guestCFCall(t, guest, "_CFURLCopyFileSystemPath", url, 0)
	wantLength := len(utf16.Encode([]rune(value)))
	if guestCFCall(t, guest, "_CFStringGetLength", stringRef) != uint64(wantLength) {
		t.Fatal("CFString length must count UTF-16 units")
	}
	pointer := guestCFCall(t, guest, "_CFStringGetCStringPtr", stringRef, guestUTF8)
	text, err := guest.services.readCString(pointer)
	if err != nil || text != value {
		t.Fatal("C string backing store differs")
	}
	borrowed := guestCFCall(t, guest, "_CFURLGetString", url)
	if guestCFCall(t, guest, "_CFURLGetString", url) != borrowed {
		t.Fatal("GetString did not preserve borrowed identity")
	}
	if state.objects[borrowed].text != "file:///guest/a%20%2520%23%F0%90%80%80/" {
		t.Fatalf("incorrect file URL escaping: %s", state.objects[borrowed].text)
	}
	guestCFCall(t, guest, "_CFRetain", borrowed)
	guestCFCall(t, guest, "_CFRelease", url)
	if state.objects[borrowed].refs != 1 || state.objects[stringRef].refs != 1 {
		t.Fatal("copied or retained strings were destroyed with their URL")
	}
	guestCFCall(t, guest, "_CFRelease", borrowed)
	if _, err := guest.invoke(guest.services.symbols["_CFStringGetLength"], borrowed); err == nil {
		t.Fatal("use after release accepted")
	}
	if _, err := guest.invoke(guest.services.symbols["_CFRelease"], borrowed); err == nil {
		t.Fatal("double release accepted")
	}
}

func TestGuestCFURLRejectsInvalidInputsAndShortBuffers(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []uint64{0, guestMaxPathBytes + 1, math.MaxUint64} {
		if guestCFCall(t, guest, "_CFURLCreateFromFileSystemRepresentation", 0, scratchBase, length, 0) != 0 {
			t.Fatal("invalid path length accepted")
		}
	}
	if guestURL(t, guest, "/a\x00b", false) != 0 {
		t.Fatal("embedded NUL accepted")
	}
	if err := guest.engine.MemWrite(scratchBase, []byte("relative")); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_CFURLCreateFromFileSystemRepresentation"], 0, scratchBase, 8, 0); err == nil {
		t.Fatal("unimplemented relative resolution was silently accepted")
	}
	url := guestURL(t, guest, "/guest/buffer", false)
	const buffer = scratchBase + 0x2000
	sentinel := bytes.Repeat([]byte{0xa5}, 32)
	if err := guest.engine.MemWrite(buffer, sentinel); err != nil {
		t.Fatal(err)
	}
	if guestCFCall(t, guest, "_CFURLGetFileSystemRepresentation", url, 1, buffer, 3) != 0 {
		t.Fatal("short output buffer accepted")
	}
	data, err := guest.engine.MemRead(buffer, uint64(len(sentinel)))
	if err != nil || !bytes.Equal(data, sentinel) {
		t.Fatal("short output wrote partial data")
	}
	for len(state.objects) < guestMaxCFObjects {
		if _, err := state.newObject(guestCFURLType, "/guest", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := state.newObject(guestCFURLType, "/guest", false); err == nil {
		t.Fatal("object bound ignored")
	}
}

func TestGuestCFURLRequiresExplicitInstallation(t *testing.T) {
	guest := newServiceTestMachine(t)
	address, err := guest.services.resolve("_CFURLCreateFromFileSystemRepresentation")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := guest.invoke(address, 0, scratchBase, 0, 0); err != nil || result != fakeHandle {
		t.Fatal("uninstalled CFURL provider changed the default runtime")
	}
	if _, err := installGuestCFURL(guest.services, nil); err != nil {
		t.Fatal(err)
	}
	if guestCFCall(t, guest, "_CFRelease", 0xdeadbeef) != 0 {
		t.Fatal("non-managed release changed existing behavior")
	}
}
