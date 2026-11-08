package machine

import (
	"errors"
	"testing"
)

func TestGuestRunLoopCapturesAndRetainsCallbacks(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := installGuestRunLoop(cf)
	if err != nil {
		t.Fatal(err)
	}
	port := guestCFCall(t, guest, "_CFMachPortCreateWithPort", 0, 0x2000, returnAddress, 0, 0)
	if got := guestCFCall(t, guest, "_CFMachPortGetPort", port); got != 0x2000 {
		t.Fatal("Mach port number changed")
	}
	source := guestCFCall(t, guest, "_CFMachPortCreateRunLoopSource", 0, port, 0)
	main := guestCFCall(t, guest, "_CFRunLoopGetMain")
	if got := guestCFCall(t, guest, "_CFRunLoopGetMain"); got != main {
		t.Fatal("main loop identity changed")
	}
	guestCFCall(t, guest, "_CFRunLoopAddSource", main, source, loop.mode)
	guestCFCall(t, guest, "_CFRunLoopAddSource", main, source, loop.mode)
	if cf.objects[source].refs != 2 {
		t.Fatal("duplicate scheduling retained a source twice")
	}
	guestCFCall(t, guest, "_CFRelease", port)
	guestCFCall(t, guest, "_CFRelease", source)
	if cf.objects[port].refs != 1 || cf.objects[source].refs != 1 {
		t.Fatal("scheduled callback was released too soon")
	}
	if _, err := guest.invoke(guest.services.symbols["_CFRunLoopRun"]); !errors.Is(err, errGuestRunLoopReady) || !loop.waiting {
		t.Fatal("run-loop boundary was reported as success or not reached")
	}
	if len(loop.ports) != 1 || loop.ports[port].callback != returnAddress {
		t.Fatal("callback entry was not captured")
	}
	guestCFCall(t, guest, "_CFMachPortInvalidate", port)
	if !loop.invalid[port] || loop.active[source] || cf.objects[source].refs != 0 || cf.objects[port].refs != 0 || len(cf.objects[main].owned) != 0 {
		t.Fatal("invalidated port retained an active source or leaked its scheduled ownership")
	}
	if _, err := guest.invoke(guest.services.symbols["_CFMachPortCreateRunLoopSource"], 0, port, 0); err == nil {
		t.Fatal("invalidated port accepted a source")
	}
}

func TestGuestRunLoopRejectsUnsupportedObjects(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := installGuestRunLoop(cf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_CFRunLoopRun"]); err == nil || loop.waiting {
		t.Fatal("empty event loop was treated as ready")
	}
	if _, err := guest.invoke(guest.services.symbols["_CFMachPortCreateRunLoopSource"], 0, 0xdead, 0); err == nil {
		t.Fatal("unknown port accepted")
	}
	if err := guest.services.writeUint64(scratchBase, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_CFMachPortCreateWithPort"], 0, 0x2000, returnAddress, scratchBase, 0); err == nil {
		t.Fatal("unsupported context version accepted")
	}
}

func TestGuestRunLoopAllocatesDistinctGuestPorts(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := installGuestRunLoop(cf)
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.services.writeUint64(scratchBase+8, 0x1234); err != nil {
		t.Fatal(err)
	}
	first := guestCFCall(t, guest, "_CFMachPortCreate", 0, returnAddress, scratchBase, scratchBase+0x100)
	second := guestCFCall(t, guest, "_CFMachPortCreate", 0, returnAddress, 0, 0)
	if first == second || loop.ports[first].port == loop.ports[second].port || loop.ports[first].info != 0x1234 {
		t.Fatal("new Mach ports lost distinct identities or context")
	}
	if got := guestCFCall(t, guest, "_CFMachPortGetPort", first); got != loop.ports[first].port {
		t.Fatal("new port number changed")
	}
	flag, err := guest.engine.MemRead(scratchBase+0x100, 1)
	if err != nil || flag[0] != 0 {
		t.Fatal("shouldFreeInfo not cleared")
	}
	guestCFCall(t, guest, "_CFRelease", first)
	if _, err := guest.invoke(guest.services.symbols["_CFMachPortGetPort"], first); err == nil {
		t.Fatal("released new port accepted")
	}
}
