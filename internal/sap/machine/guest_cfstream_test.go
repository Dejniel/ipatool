package machine

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"howett.net/plist"
)

func TestGuestCFStreamNeverFallsBackToHost(t *testing.T) {
	guest := newServiceTestMachine(t)
	seed := []byte("private guest bytes")
	_, err := installGuestCFURL(guest.services, map[string][]byte{"/guest/file": seed})
	if err != nil {
		t.Fatal(err)
	}
	seed[0] = 0
	for _, name := range []string{"/etc/passwd", "/Users/Shared/SC Info/SC Info.sidb", "/private/var/db/fpsd/SC Info/SC Info.sidb"} {
		url := guestURL(t, guest, name, false)
		stream := guestCFCall(t, guest, "_CFReadStreamCreateWithFile", 0, url)
		if guestCFCall(t, guest, "_CFReadStreamOpen", stream) != 0 {
			t.Fatalf("unseeded path opened: %s", name)
		}
	}
	url := guestURL(t, guest, "/guest/file", false)
	stream := guestCFCall(t, guest, "_CFReadStreamCreateWithFile", 0, url)
	if guestCFCall(t, guest, "_CFReadStreamOpen", stream) != 1 {
		t.Fatal("seeded file did not open")
	}
	const buffer = scratchBase + 0x2000
	if guestCFCall(t, guest, "_CFReadStreamRead", stream, buffer, 7) != 7 {
		t.Fatal("short read count differs")
	}
	data, err := guest.engine.MemRead(buffer, 7)
	if err != nil || !bytes.Equal(data, []byte("private")) {
		t.Fatal("seed was not copied or stream read changed bytes")
	}
	if guestCFCall(t, guest, "_CFReadStreamRead", stream, buffer, 100) != 12 {
		t.Fatal("remaining read count differs")
	}
	if guestCFCall(t, guest, "_CFReadStreamRead", stream, buffer, 100) != 0 {
		t.Fatal("EOF was not reported")
	}
	guestCFCall(t, guest, "_CFReadStreamClose", stream)
	if guestCFCall(t, guest, "_CFReadStreamRead", stream, buffer, 100) != math.MaxUint64 {
		t.Fatal("closed stream read did not fail")
	}
	if guestCFCall(t, guest, "_CFReadStreamOpen", stream) != 0 {
		t.Fatal("closed stream reopened")
	}
}

func TestGuestCFPropertyListFormatsAndBorrowedValues(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		guest := newServiceTestMachine(t)
		data, err := plist.Marshal(map[string]string{"ProductVersion": "27.0.1"}, format)
		if err != nil {
			t.Fatal(err)
		}
		state, err := installGuestCFURL(guest.services, map[string][]byte{"/guest/version": data})
		if err != nil {
			t.Fatal(err)
		}
		url := guestURL(t, guest, "/guest/version", false)
		stream := guestCFCall(t, guest, "_CFReadStreamCreateWithFile", 0, url)
		guestCFCall(t, guest, "_CFReadStreamOpen", stream)
		const formatOut, errorOut = scratchBase + 0x2000, scratchBase + 0x2008
		dictionary := guestCFCall(t, guest, "_CFPropertyListCreateWithStream", 0, stream, 0, 0, formatOut, errorOut)
		wantFormat := uint64(100)
		if format == plist.BinaryFormat {
			wantFormat = 200
		}
		if actual, err := guest.services.readUint64(formatOut); err != nil || actual != wantFormat {
			t.Fatal("native CF plist format value differs")
		}
		if actual, err := guest.services.readUint64(errorOut); err != nil || actual != 0 {
			t.Fatal("successful parse reported an error")
		}
		const key = scratchBase + 0x2100
		const keyBytes = key + 0x100
		var literal [32]byte
		binary.LittleEndian.PutUint64(literal[8:16], 0x7c8)
		binary.LittleEndian.PutUint64(literal[16:24], keyBytes)
		binary.LittleEndian.PutUint64(literal[24:32], uint64(len("ProductVersion")))
		if err := guest.engine.MemWrite(key, literal[:]); err != nil {
			t.Fatal(err)
		}
		if err := guest.engine.MemWrite(keyBytes, []byte("ProductVersion")); err != nil {
			t.Fatal(err)
		}
		value := guestCFCall(t, guest, "_CFDictionaryGetValue", dictionary, key)
		if state.objects[value].text != "27.0.1" {
			t.Fatal("dictionary key resolution differs")
		}
		guestCFCall(t, guest, "_CFRelease", dictionary)
		if state.objects[value].refs != 0 {
			t.Fatal("dictionary did not release its owned value")
		}
	}
}

func TestGuestCFStreamRejectsUnsupportedPlistAndLargeSeed(t *testing.T) {
	guest := newServiceTestMachine(t)
	if _, err := installGuestCFURL(guest.services, map[string][]byte{"/guest/large": make([]byte, (1<<20)+1)}); err == nil {
		t.Fatal("oversized virtual file accepted")
	}
	if _, err := installGuestCFURL(guest.services, map[string][]byte{"relative": []byte("x")}); err == nil {
		t.Fatal("relative virtual file accepted")
	}
	if _, err := installGuestCFURL(guest.services, map[string][]byte{"/guest/bad": []byte("invalid plist")}); err != nil {
		t.Fatal(err)
	}
	url := guestURL(t, guest, "/guest/bad", false)
	stream := guestCFCall(t, guest, "_CFReadStreamCreateWithFile", 0, url)
	guestCFCall(t, guest, "_CFReadStreamOpen", stream)
	if _, err := guest.invoke(guest.services.symbols["_CFPropertyListCreateWithStream"], 0, stream, 0, 0, 0, 0); err == nil {
		t.Fatal("malformed plist silently accepted")
	}
}
