package machine

import "errors"

const guestMaxFileBytes = 4 << 20

func (state *guestFiles) installBackupMetadata(cf *guestCFURLs) error {
	return cf.replace("_CSBackupSetItemExcluded", func() error {
		url, err := state.guest.argument(0)
		if err != nil {
			return err
		}
		exclude, err := state.guest.argument(1)
		if err != nil {
			return err
		}
		byPath, err := state.guest.argument(2)
		if err != nil {
			return err
		}
		object := cf.objects[url]
		if object == nil || object.kind != guestCFURLType || object.refs == 0 || exclude > 1 || byPath != 0 {
			return errors.New("unsupported guest backup metadata request")
		}
		file := state.files[object.text]
		if file == nil {
			return errors.New("guest backup target does not exist")
		}
		file.backupExcluded = exclude != 0
		return state.guest.setResult(0)
	})
}

func (state *guestFiles) installIO() error {
	for name, handler := range map[string]shimHandler{
		"_read": state.read, "_read$UNIX2003": state.read,
		"_write": state.write, "_write$UNIX2003": state.write,
		"_lseek": state.seek, "_ftruncate": state.truncate,
		"_fsync": state.sync, "_fstat": state.fstat, "_fstat$INODE64": state.fstat,
	} {
		address, err := state.guest.resolve(name)
		if err != nil {
			return err
		}
		original := state.guest.entries[address].handler
		state.guest.entries[address] = shimEntry{name: name, handler: func() error {
			if name == "_read" || name == "_read$UNIX2003" {
				fd, err := state.guest.argument(0)
				if err != nil {
					return err
				}
				if fd == coreFPFile {
					return original()
				}
			}
			return handler()
		}}
	}
	return nil
}

func (state *guestFiles) transfer(write bool) error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	buffer, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	count, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	descriptor := state.descriptors[fd]
	if descriptor == nil || (write && descriptor.flags&3 == 0) || (!write && descriptor.flags&3 == guestWriteOnly) {
		return state.fail(9)
	}
	if count > guestMaxFileBytes || descriptor.position < 0 || descriptor.position > guestMaxFileBytes {
		return errors.New("guest file transfer bounds exceeded")
	}
	if count == 0 {
		return state.guest.setResult(0)
	}
	position := int(descriptor.position)
	if write && descriptor.flags&guestAppend != 0 {
		position = len(descriptor.file.data)
	}
	if write {
		if count > uint64(guestMaxFileBytes-position) {
			return errors.New("guest file extent exceeded")
		}
		data, err := state.guest.engine.MemRead(buffer, count)
		if err != nil {
			return err
		}
		end := position + int(count)
		if end > len(descriptor.file.data) {
			descriptor.file.data = append(descriptor.file.data, make([]byte, end-len(descriptor.file.data))...)
		}
		copy(descriptor.file.data[position:end], data)
	} else {
		if position >= len(descriptor.file.data) {
			return state.guest.setResult(0)
		}
		count = min(count, uint64(len(descriptor.file.data)-position))
		if err := state.guest.engine.MemWrite(buffer, descriptor.file.data[position:position+int(count)]); err != nil {
			return err
		}
	}
	descriptor.position = int64(position) + int64(count)
	return state.guest.setResult(count)
}

func (state *guestFiles) read() error  { return state.transfer(false) }
func (state *guestFiles) write() error { return state.transfer(true) }

func (state *guestFiles) seek() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	raw, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	whence, err := state.guest.argument(2)
	if err != nil {
		return err
	}
	descriptor := state.descriptors[fd]
	if descriptor == nil {
		return state.fail(9)
	}
	var base int64
	switch whence {
	case 0:
	case 1:
		base = descriptor.position
	case 2:
		base = int64(len(descriptor.file.data))
	default:
		return state.fail(22)
	}
	offset := int64(raw)
	if offset > guestMaxFileBytes-base || offset < -base {
		return state.fail(22)
	}
	descriptor.position = base + offset
	return state.guest.setResult(uint64(descriptor.position))
}

func (state *guestFiles) truncate() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	size, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	descriptor := state.descriptors[fd]
	if descriptor == nil || descriptor.flags&3 == 0 {
		return state.fail(9)
	}
	if size > guestMaxFileBytes {
		return errors.New("guest truncate extent exceeded")
	}
	data := make([]byte, int(size))
	copy(data, descriptor.file.data)
	clear(descriptor.file.data)
	descriptor.file.data = data
	return state.guest.setResult(0)
}

func (state *guestFiles) sync() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	if state.descriptors[fd] == nil {
		return state.fail(9)
	}
	return state.guest.setResult(0)
}

func (state *guestFiles) fstat() error {
	fd, err := state.guest.argument(0)
	if err != nil {
		return err
	}
	output, err := state.guest.argument(1)
	if err != nil {
		return err
	}
	descriptor := state.descriptors[fd]
	if descriptor == nil {
		return state.fail(9)
	}
	return state.writeStat(output, 0100000|descriptor.file.mode, uint64(len(descriptor.file.data)))
}
