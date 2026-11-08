package machine

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestGuestFileIOKeepsContentsInGuestRAM(t *testing.T) {
	guest := newServiceTestMachine(t)
	state, err := installGuestFiles(guest.services)
	if err != nil {
		t.Fatal(err)
	}
	const name = "/var/db/fpsd/SC Info/SC Info.sidb"
	fd, err := guestOpen(t, guest, name, guestReadWrite|guestCreate|guestOpenLock, 0600)
	if err != nil || !state.files[name].locked {
		t.Fatal("exclusive virtual open did not acquire its lock")
	}
	const buffer = scratchBase + 0x2000
	if err := guest.engine.MemWrite(buffer, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_write", fd, buffer, 3); got != 3 {
		t.Fatal("virtual write failed")
	}
	guestCFCall(t, guest, "_lseek", fd, 5, 0)
	if got := guestCFCall(t, guest, "_write", fd, 0xdead, 0); got != 0 || len(state.files[name].data) != 3 {
		t.Fatal("zero-byte write extended the file")
	}
	guestCFCall(t, guest, "_write", fd, buffer, 1)
	if !bytes.Equal(state.files[name].data, []byte{'a', 'b', 'c', 0, 0, 'a'}) {
		t.Fatal("sparse virtual write lost zero padding")
	}
	guestCFCall(t, guest, "_lseek", fd, 0, 0)
	if got := guestCFCall(t, guest, "_read", fd, buffer, 32); got != 6 {
		t.Fatal("virtual read did not stop at EOF")
	}
	guestCFCall(t, guest, "_fstat", fd, buffer+128)
	metadata, err := guest.engine.MemRead(buffer+128, 144)
	if err != nil || binary.LittleEndian.Uint64(metadata[96:]) != 6 || binary.LittleEndian.Uint16(metadata[4:]) != 0100600 {
		t.Fatal("fstat lost virtual file geometry")
	}
	guestCFCall(t, guest, "_ftruncate", fd, 2)
	if !bytes.Equal(state.files[name].data, []byte("ab")) || state.descriptors[fd].position != 6 {
		t.Fatal("truncate changed the file offset or wrong data")
	}
	guestCFCall(t, guest, "_fsync", fd)
	if _, err := guest.invoke(guest.services.symbols["_write"], fd, buffer, guestMaxFileBytes+1); err == nil {
		t.Fatal("oversized virtual transfer accepted")
	}
	guestCFCall(t, guest, "_close", fd)
	readOnly, err := guestOpen(t, guest, name, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := guestCFCall(t, guest, "_write", readOnly, buffer, 1); int64(got) != -1 {
		t.Fatal("read-only descriptor accepted a write")
	}
}

func TestGuestBackupMetadataIsGuestLocal(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := installGuestFiles(guest.services)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.installBackupMetadata(cf); err != nil {
		t.Fatal(err)
	}
	const name = "/var/db/fpsd/SC Info/SC Info.sidb"
	if _, err := guestOpen(t, guest, name, guestReadWrite|guestCreate, 0600); err != nil {
		t.Fatal(err)
	}
	url := guestURL(t, guest, name, false)
	guestCFCall(t, guest, "_CSBackupSetItemExcluded", url, 1, 0)
	if !state.files[name].backupExcluded {
		t.Fatal("virtual backup exclusion was not stored")
	}
	guestCFCall(t, guest, "_CSBackupSetItemExcluded", url, 0, 0)
	if state.files[name].backupExcluded {
		t.Fatal("virtual backup exclusion was not cleared")
	}
	if _, err := guest.invoke(guest.services.symbols["_CSBackupSetItemExcluded"], url, 1, 1); err == nil {
		t.Fatal("unsupported path-based exclusion accepted")
	}
	guestCFCall(t, guest, "_CFRelease", url)
	if _, err := guest.invoke(guest.services.symbols["_CSBackupSetItemExcluded"], url, 1, 0); err == nil {
		t.Fatal("released URL accepted")
	}
	missing := guestURL(t, guest, "/var/db/fpsd/SC Info/absent", false)
	if _, err := guest.invoke(guest.services.symbols["_CSBackupSetItemExcluded"], missing, 1, 0); err == nil {
		t.Fatal("absent backup target accepted")
	}
}
