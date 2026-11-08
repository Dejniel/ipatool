package machine

import "testing"

func TestGuestIOKitDoesNotInventHardware(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	iokit, err := installGuestIOKit(cf)
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(scratchBase, []byte("com_apple_driver_FairPlayIOKit\x00")); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x2000
	guestCFCall(t, guest, "_IOMainPort", 0, output)
	port, err := guest.services.readUint32(output)
	if err != nil || port != 0x3000 {
		t.Fatal("virtual IOKit namespace unavailable")
	}
	matching := guestCFCall(t, guest, "_IOServiceMatching", scratchBase)
	if len(iokit.queries) != 1 || iokit.queries[0] != "com_apple_driver_FairPlayIOKit" {
		t.Fatal("IOKit provider query changed")
	}
	guestCFCall(t, guest, "_IOServiceGetMatchingServices", uint64(port), matching, output)
	if cf.objects[matching].refs != 0 {
		t.Fatal("IOKit did not consume its matching dictionary")
	}
	iterator, err := guest.services.readUint32(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_IOIteratorNext", uint64(iterator)); got != 0 {
		t.Fatal("a nonexistent hardware provider was returned")
	}
	guestCFCall(t, guest, "_IOObjectRelease", uint64(iterator))
	if _, err := guest.invoke(guest.services.symbols["_IOIteratorNext"], uint64(iterator)); err == nil {
		t.Fatal("released iterator accepted")
	}
}
