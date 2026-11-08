package machine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
)

// Constants are Darwin values, not the Linux host's syscall constants.
const (
	guestWriteOnly = uint64(1)
	guestReadWrite = uint64(2)
	guestAppend    = uint64(8)
	guestOpenLock  = uint64(0x20)
	guestNoFollow  = uint64(0x100)
	guestCreate    = uint64(0x200)
	guestTruncate  = uint64(0x400)
	guestExclusive = uint64(0x800)
	guestCloseExec = uint64(0x1000000)
)

type guestFile struct {
	data           []byte
	mode           uint64
	locked         bool
	backupExcluded bool
}

type guestDescriptor struct {
	file     *guestFile
	name     string
	flags    uint64
	position int64
}

type guestFiles struct {
	guest       *shims
	mask        uint64
	next        uint64
	files       map[string]*guestFile
	descriptors map[uint64]*guestDescriptor
}

func installGuestFiles(guest *shims) (*guestFiles, error) {
	state := &guestFiles{guest: guest, mask: 0022, next: 100, files: map[string]*guestFile{}, descriptors: map[uint64]*guestDescriptor{}}
	for name, handler := range map[string]shimHandler{
		"_umask":           state.umask,
		"_open":            state.open,
		"_open$UNIX2003":   state.open,
		"_close":           state.close,
		"_close$UNIX2003":  state.close,
		"_fcntl":           state.fcntl,
		"_fcntl$UNIX2003":  state.fcntl,
		"_lockf":           state.lockf,
		"_statfs":          state.statfs,
		"_statfs$INODE64":  state.statfs,
		"_statfs$UNIX2003": state.statfs,
		"_stat":            state.stat,
		"_stat$INODE64":    state.stat,
		"_lstat":           state.stat,
		"_lstat$INODE64":   state.stat,
	} {
		address, err := guest.resolve(name)
		if err != nil {
			return nil, err
		}
		original := guest.entries[address].handler
		guest.entries[address] = shimEntry{name: name, handler: func() error {
			first, err := guest.argument(0)
			if err != nil {
				return err
			}
			if name == "_close" || name == "_close$UNIX2003" {
				if first == coreFPFile {
					return original()
				}
			} else if name == "_open" || name == "_open$UNIX2003" {
				value, err := guest.readCString(first)
				if err != nil {
					return err
				}
				if value == icxsPath {
					return original()
				}
			}
			return handler()
		}}
	}
	if err := state.installIO(); err != nil {
		return nil, err
	}
	return state, nil
}

func (state *guestFiles) stat() error {
	namePointer, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	name, err := state.guest.readCString(namePointer)
	if err != nil {
		return err
	}
	name = path.Clean(name)
	output, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	mode := uint64(0040755)
	size := uint64(0)
	switch name {
	case "/", "/var", "/var/db", "/var/db/fpsd", "/var/db/fpsd/SC Info", "/Users", "/Users/Shared", "/Users/Shared/SC Info":
	default:
		file, exists := state.files[name]
		if !exists {
			return state.fail(2)
		}
		mode = 0100000 | file.mode
		size = uint64(len(file.data))
	}
	return state.writeStat(output, mode, size)
}

func (state *guestFiles) writeStat(output, mode, size uint64) error {
	data := make([]byte, 144) // Darwin arm64 struct stat, including its padding.
	binary.LittleEndian.PutUint32(data[0:4], 1)
	binary.LittleEndian.PutUint16(data[4:6], uint16(mode))
	binary.LittleEndian.PutUint16(data[6:8], 1)
	binary.LittleEndian.PutUint64(data[8:16], 1)
	binary.LittleEndian.PutUint32(data[16:20], 501)
	binary.LittleEndian.PutUint32(data[20:24], 501)
	binary.LittleEndian.PutUint64(data[96:104], size)
	binary.LittleEndian.PutUint64(data[104:112], (size+511)/512)
	binary.LittleEndian.PutUint32(data[112:116], 4096)
	if err := state.guest.engine.MemWrite(output, data); err != nil {
		return err
	}
	return state.guest.setResult(0)
}

func (state *guestFiles) fail(errno uint32) error {
	if err := state.guest.writeUint32(state.guest.errno, errno); err != nil {
		return err
	}
	return state.guest.returnMinusOne()
}

func (state *guestFiles) umask() error {
	value, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	previous := state.mask
	state.mask = value & 0777
	return state.guest.setResult(previous)
}

func guestWritablePath(name string) bool {
	if path.Clean(name) != name {
		return false
	}
	return path.Dir(name) == "/var/db/fpsd/SC Info" || path.Dir(name) == "/Users/Shared/SC Info"
}

func (state *guestFiles) open() error {
	pointer, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	name, err := state.guest.readCString(pointer)
	if err != nil {
		return err
	}
	flags, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	if !guestWritablePath(name) {
		return state.fail(2) // ENOENT; never fall back to the host filesystem.
	}
	const supported = 3 | guestAppend | guestOpenLock | guestNoFollow | guestCreate | guestTruncate | guestExclusive | guestCloseExec
	if flags & ^uint64(supported) != 0 || flags&3 == 3 {
		return errors.New("unsupported guest open flags")
	}
	if flags&guestTruncate != 0 && flags&3 == 0 {
		return errors.New("guest truncate requires write access")
	}
	if len(state.descriptors) >= 32 {
		return state.fail(24) // EMFILE
	}
	file, exists := state.files[name]
	if !exists {
		if flags&guestCreate == 0 {
			return state.fail(2)
		}
		if len(state.files) >= 32 {
			return errors.New("guest file limit reached")
		}
		mode, err := state.guest.argument(8)
		if err != nil {
			return err
		}
		file = &guestFile{mode: mode & 0777 & ^state.mask}
		state.files[name] = file
	} else if flags&(guestCreate|guestExclusive) == guestCreate|guestExclusive {
		return state.fail(17) // EEXIST
	}
	if flags&guestOpenLock != 0 && file.locked {
		return errors.New("contended guest open lock is not modeled")
	}
	if flags&guestTruncate != 0 {
		file.data = nil
	}
	descriptor := state.next
	state.next++
	state.descriptors[descriptor] = &guestDescriptor{file: file, name: name, flags: flags}
	if flags&guestOpenLock != 0 {
		file.locked = true
	}
	return state.guest.setResult(descriptor)
}

func (state *guestFiles) close() error {
	descriptor, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	file, exists := state.descriptors[descriptor]
	if !exists {
		return state.fail(9) // EBADF
	}
	file.file.locked = false
	delete(state.descriptors, descriptor)
	return state.guest.setResult(0)
}

func (state *guestFiles) fcntl() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	descriptor, exists := state.descriptors[fd]
	if !exists {
		return state.fail(9)
	}
	command, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	switch command {
	case 1: // F_GETFD
		return state.guest.setResult((descriptor.flags & guestCloseExec) >> 24)
	case 2: // F_SETFD; the third argument is variadic on Darwin ARM64.
		flags, err := state.guest.argument(8)
		if err != nil {
			return err
		}
		if flags & ^uint64(1) != 0 {
			return errors.New("unsupported guest descriptor flags")
		}
		descriptor.flags = descriptor.flags & ^guestCloseExec | flags<<24
		return state.guest.setResult(0)
	case 3: // F_GETFL
		return state.guest.setResult(descriptor.flags & (3 | guestAppend))
	case 50: // F_GETPATH writes a MAXPATHLEN (1024-byte) caller buffer.
		pointer, err := state.guest.argument(8)
		if err != nil {
			return err
		}
		if pointer == 0 || len(descriptor.name) >= 1024 {
			return errors.New("invalid guest F_GETPATH buffer or path")
		}
		if err := state.guest.engine.MemWrite(pointer, append([]byte(descriptor.name), 0)); err != nil {
			return err
		}
		return state.guest.setResult(0)
	default:
		return fmt.Errorf("unsupported guest fcntl command %d", command)
	}
}

func (state *guestFiles) lockf() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	descriptor, exists := state.descriptors[fd]
	if !exists || descriptor.flags&3 == 0 {
		return state.fail(9)
	}
	command, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	length, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	if length != 0 || descriptor.position != 0 {
		return errors.New("guest lockf supports whole-file locks only")
	}
	switch command {
	case 0: // F_ULOCK
		descriptor.file.locked = false
	case 1, 2: // F_LOCK / F_TLOCK; this guest is the only process.
		descriptor.file.locked = true
	case 3: // F_TEST: a process does not conflict with its own locks.
	default:
		return errors.New("unsupported guest lockf command")
	}
	return state.guest.setResult(0)
}

func (state *guestFiles) statfs() error {
	namePointer, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	name, err := state.guest.readCString(namePointer)
	if err != nil {
		return err
	}
	if name != "/" && name != "/var/db/fpsd/SC Info" && name != "/Users/Shared/SC Info" && !guestWritablePath(name) {
		return state.fail(2)
	}
	output, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	// Darwin arm64 statfs layout. This describes a synthetic 16 MiB guest
	// volume; no capacity, mount or device identity is read from the host.
	data := make([]byte, 2168)
	binary.LittleEndian.PutUint32(data[0:4], 4096)
	binary.LittleEndian.PutUint32(data[4:8], 4096)
	for _, offset := range []int{8, 16, 24} {
		binary.LittleEndian.PutUint64(data[offset:offset+8], 4096)
	}
	binary.LittleEndian.PutUint64(data[32:40], 32)
	binary.LittleEndian.PutUint64(data[40:48], uint64(32-len(state.files)))
	binary.LittleEndian.PutUint32(data[48:52], 1)
	binary.LittleEndian.PutUint32(data[56:60], 501)
	binary.LittleEndian.PutUint32(data[60:64], 24)
	binary.LittleEndian.PutUint32(data[64:68], 0x1000)
	copy(data[72:88], "apfs")
	copy(data[88:1112], "/")
	copy(data[1112:2136], "guest-memory")
	if err := state.guest.engine.MemWrite(output, data); err != nil {
		return err
	}
	return state.guest.setResult(0)
}
