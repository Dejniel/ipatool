package machine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func guestOpen(t *testing.T, guest *Machine, name string, flags, mode uint64) (uint64, error) {
	t.Helper()
	if err := guest.engine.MemWrite(scratchBase, append([]byte(name), 0)); err != nil {
		t.Fatal(err)
	}
	return guest.invoke(guest.services.symbols["_open"], scratchBase, flags, 0xdead, 0xdead, 0xdead, 0xdead, 0xdead, 0xdead, mode)
}

func TestGuestFilesCreationFlagsAndOwnership(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestFiles(guest.services)
	if err != nil {
		t.Fatal(err)
	}
	const name = "/var/db/fpsd/SC Info/.sid.lockFile"
	guestCFCall(t, guest, "_umask", 0077)
	fd, err := guestOpen(t, guest, name, guestWriteOnly|guestCreate|guestCloseExec, 0666)
	if err != nil || fd < 100 {
		t.Fatalf("open = %d, %v", fd, err)
	}
	if state.files[name].mode != 0600 {
		t.Fatalf("umask or Darwin mode argument lost: mode %o", state.files[name].mode)
	}
	if got := guestCFCall(t, guest, "_fcntl", fd, 1); got != 1 {
		t.Fatal("close-on-exec flag lost")
	}
	if _, err := guest.invoke(guest.services.symbols["_fcntl"], fd, 2, 0xdead, 0, 0, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_fcntl", fd, 1); got != 0 {
		t.Fatal("F_SETFD ignored the Darwin stack argument")
	}
	const pathOutput = scratchBase + 0x2000
	if _, err := guest.invoke(guest.services.symbols["_fcntl"], fd, 50, 0xdead, 0, 0, 0, 0, 0, pathOutput); err != nil {
		t.Fatal(err)
	}
	if value, err := guest.services.readCString(pathOutput); err != nil || value != name {
		t.Fatal("F_GETPATH did not return the virtual path")
	}
	for _, command := range []uint64{1, 3, 0, 2} {
		if got := guestCFCall(t, guest, "_lockf", fd, command, 0); got != 0 {
			t.Fatal("whole-file lock operation failed")
		}
	}
	if !state.files[name].locked {
		t.Fatal("file lock was not recorded")
	}
	guestCFCall(t, guest, "_close", fd)
	if state.files[name].locked || len(state.descriptors) != 0 {
		t.Fatal("close did not release descriptor and lock")
	}
	fd, err = guestOpen(t, guest, name, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_lockf", fd, 1, 0); int64(got) != -1 {
		t.Fatal("write lock on read-only descriptor accepted")
	}
	if got, err := guestOpen(t, guest, name, guestCreate|guestExclusive|guestWriteOnly, 0600); err != nil || int64(got) != -1 {
		t.Fatal("exclusive creation replaced an existing file")
	}
	if errno, err := guest.services.readUint32(guest.services.errno); err != nil || errno != 17 {
		t.Fatal("EEXIST was not recorded")
	}
}

func TestGuestFilesNeverReadHostOrEscapeRoots(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestFiles(guest.services)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/etc/passwd", "/Users/Shared/SC Info/../secret", "/var/db/fpsd/SC Info/sub/file", "SC Info.sidb", "/private/var/db/fpsd/SC Info/SC Info.sidb"} {
		fd, err := guestOpen(t, guest, name, guestCreate|guestReadWrite, 0600)
		if err != nil || int64(fd) != -1 {
			t.Fatalf("host/escape path accepted: %s", name)
		}
	}
	if len(state.files) != 0 || len(state.descriptors) != 0 {
		t.Fatal("rejected paths changed virtual storage")
	}
	fd, err := guestOpen(t, guest, "/Users/Shared/SC Info/SC Info.sidb", 0, 0)
	if err != nil || int64(fd) != -1 {
		t.Fatal("an absent virtual SIDB was silently provided")
	}
	if _, err := guestOpen(t, guest, "/Users/Shared/SC Info/SC Info.sidb", 0x80000000, 0); err == nil {
		t.Fatal("unsupported open flags accepted")
	}
	if got := guestCFCall(t, guest, "_close", 0xdead); int64(got) != -1 {
		t.Fatal("unknown descriptor accepted")
	}
}

func TestGuestFilesBoundsAndFreshState(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestFiles(guest.services)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		name := fmt.Sprintf("/var/db/fpsd/SC Info/test-%d", index)
		if _, err := guestOpen(t, guest, name, guestCreate|guestReadWrite, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.files) != 32 || len(state.descriptors) != 32 {
		t.Fatal("virtual file accounting differs")
	}
	if value, err := guestOpen(t, guest, "/var/db/fpsd/SC Info/overflow", guestCreate|guestReadWrite, 0600); err != nil || int64(value) != -1 {
		t.Fatal("descriptor count bound ignored")
	}
	for fd := range state.descriptors {
		guestCFCall(t, guest, "_close", fd)
	}
	if _, err := guestOpen(t, guest, "/var/db/fpsd/SC Info/overflow", guestCreate|guestReadWrite, 0600); err == nil {
		t.Fatal("file count bound ignored")
	}
	fresh := newServiceTestMachine(t)
	other, err := installGuestFiles(fresh.services)
	if err != nil || len(other.files) != 0 || len(other.descriptors) != 0 || other.mask != 0022 {
		t.Fatal("virtual files leaked between guests")
	}
}

func TestGuestFilesStatfsLayoutAndScope(t *testing.T) {
	guest := newServiceTestMachine(t)
	if _, err := installGuestFiles(guest.services); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x2000
	sentinel := bytes.Repeat([]byte{0xa5}, 2176)
	if err := guest.engine.MemWrite(output, sentinel); err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(scratchBase, []byte("/var/db/fpsd/SC Info\x00")); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_statfs", scratchBase, output); got != 0 {
		t.Fatal("virtual statfs failed")
	}
	data, err := guest.engine.MemRead(output, uint64(len(sentinel)))
	if err != nil || binary.LittleEndian.Uint32(data[:4]) != 4096 || binary.LittleEndian.Uint64(data[8:16]) != 4096 || !bytes.Equal(data[2168:], sentinel[2168:]) {
		t.Fatal("Darwin statfs layout or extent differs")
	}
	if !bytes.HasPrefix(data[72:88], []byte("apfs\x00")) || !bytes.HasPrefix(data[1112:2136], []byte("guest-memory\x00")) {
		t.Fatal("synthetic guest mount identity differs")
	}
	if err := guest.engine.MemWrite(scratchBase, []byte("/etc/passwd\x00")); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_statfs", scratchBase, output); int64(got) != -1 {
		t.Fatal("statfs inspected an unknown host path")
	}
}

func TestGuestFilesStatUsesDarwinLayout(t *testing.T) {
	guest := newServiceTestMachine(t)
	if _, err := installGuestFiles(guest.services); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x2000
	if err := guest.engine.MemWrite(scratchBase, []byte("/var/db/fpsd/SC Info/\x00")); err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(output, bytes.Repeat([]byte{0xa5}, 152)); err != nil {
		t.Fatal(err)
	}
	guestCFCall(t, guest, "_stat", scratchBase, output)
	data, err := guest.engine.MemRead(output, 152)
	if err != nil || binary.LittleEndian.Uint16(data[4:6]) != 0040755 || binary.LittleEndian.Uint32(data[16:20]) != 501 || binary.LittleEndian.Uint64(data[96:104]) != 0 || !bytes.Equal(data[144:], bytes.Repeat([]byte{0xa5}, 8)) {
		t.Fatal("Darwin stat layout, directory normalization or extent differs")
	}
}
