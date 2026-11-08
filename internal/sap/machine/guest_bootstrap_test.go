package machine

import "testing"

func TestGuestBootstrapReportsAbsentService(t *testing.T) {
	guest := newServiceTestMachine(t)
	if _, err := installGuestBootstrap(guest.services, nil); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x2000
	if err := guest.engine.MemWrite(scratchBase, []byte("com.apple.fpsd\x00")); err != nil {
		t.Fatal(err)
	}
	if err := guest.services.writeUint32(output, 0xa5a5a5a5); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_bootstrap_look_up", 0, scratchBase, output); got != 1102 {
		t.Fatal("missing service was not reported as BOOTSTRAP_UNKNOWN_SERVICE")
	}
	if got, err := guest.services.readUint32(output); err != nil || got != 0 {
		t.Fatal("missing service returned a non-null port")
	}
	if _, err := guest.invoke(guest.services.symbols["_bootstrap_look_up"], 0, scratchBase, 0); err == nil {
		t.Fatal("null output accepted")
	}
}

func TestGuestBootstrapReservationsAndCheckIn(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestBootstrap(guest.services, []string{"com.apple.fpsd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(scratchBase, []byte("com.apple.fpsd\x00")); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x2000
	if got := guestCFCall(t, guest, "_bootstrap_look_up", 0, scratchBase, output); got != 0 {
		t.Fatal("reserved port was not discoverable")
	}
	if state.services["com.apple.fpsd"].checkedIn {
		t.Fatal("lookup acquired receive rights")
	}
	if _, err := guest.invoke(guest.services.symbols["_bootstrap_check_in"], 0, scratchBase, 0xdead); err == nil || state.services["com.apple.fpsd"].checkedIn {
		t.Fatal("failed output write consumed receive rights")
	}
	if got := guestCFCall(t, guest, "_bootstrap_check_in", 0, scratchBase, output); got != 0 {
		t.Fatal("reserved service check-in failed")
	}
	if port, err := guest.services.readUint32(output); err != nil || port != 0x2000 {
		t.Fatal("incorrect virtual receive port")
	}
	if got := guestCFCall(t, guest, "_bootstrap_check_in", 0, scratchBase, output); got != 1103 {
		t.Fatal("duplicate receive rights accepted")
	}
	if _, err := installGuestBootstrap(guest.services, []string{"duplicate", "duplicate"}); err == nil {
		t.Fatal("duplicate reservation accepted")
	}
}
