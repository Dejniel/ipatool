package machine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	guestCFTaskType = 0x10008
	guestCFBoolType = 0x10009
)

// Model one caller inside the guest, never the host's code-signing authority.
// Entitlements must come from the hash-validated client image, not a blanket
// success stub. The token identifies only this synthetic ordinary-user task.
func installGuestTaskEntitlements(cf *guestCFURLs, audit []byte, entitlements map[string]bool) (*[]string, error) {
	if len(audit) != 32 || len(entitlements) > 128 {
		return nil, errors.New("invalid guest client security metadata")
	}
	audit = bytes.Clone(audit)
	values := make(map[string]bool, len(entitlements))
	for name, value := range entitlements {
		values[name] = value
	}
	var queries []string
	guest := cf.guest
	for name, handler := range map[string]shimHandler{
		"_audit_token_to_au32": func() error {
			pointer, err := guest.argument(0)
			if err != nil {
				return err
			}
			token, err := guest.engine.MemRead(pointer, 32)
			if err != nil {
				return err
			}
			if !bytes.Equal(token, audit) {
				return errors.New("unknown guest audit identity")
			}
			terminal, err := guest.argument(8)
			if err != nil {
				return err
			}
			if terminal != 0 {
				return errors.New("guest audit terminal IDs are not modeled")
			}
			for index := 0; index < 7; index++ {
				output, err := guest.argument(index + 1)
				if err != nil {
					return err
				}
				if output != 0 {
					if err := guest.writeUint32(output, binary.LittleEndian.Uint32(token[index*4:])); err != nil {
						return err
					}
				}
			}
			return guest.setResult(0)
		},
		"_CFStringCreateWithCStringNoCopy": func() error {
			pointer, err := guest.argument(1)
			if err != nil {
				return err
			}
			encoding, err := guest.argument(2)
			if err != nil {
				return err
			}
			if encoding != guestUTF8 && encoding != 0x600 {
				return fmt.Errorf("unsupported guest caller string encoding %#x", encoding)
			}
			text, err := guest.readCString(pointer)
			if err != nil {
				return err
			}
			if !utf8.ValidString(text) {
				return errors.New("invalid guest caller UTF-8 string")
			}
			if encoding == 0x600 {
				for _, char := range []byte(text) {
					if char > 127 {
						return errors.New("invalid guest caller ASCII string")
					}
				}
			}
			handle, err := cf.newObject(guestCFStringType, text, false)
			if err != nil {
				return err
			}
			return guest.setResult(handle)
		},
		"_SecTaskCreateWithAuditToken": func() error {
			pointer, err := guest.argument(1)
			if err != nil {
				return err
			}
			token, err := guest.engine.MemRead(pointer, 32)
			if err != nil {
				return err
			}
			if !bytes.Equal(token, audit) {
				return errors.New("unknown guest audit identity")
			}
			handle, err := cf.newObject(guestCFTaskType, "", false)
			if err != nil {
				return err
			}
			return guest.setResult(handle)
		},
		"_SecTaskCopyValueForEntitlement": func() error {
			task, err := guest.argument(0)
			if err != nil {
				return err
			}
			key, err := guest.argument(1)
			if err != nil {
				return err
			}
			taskObject, keyObject := cf.objects[task], cf.objects[key]
			if taskObject == nil || taskObject.kind != guestCFTaskType || taskObject.refs == 0 {
				return errors.New("unknown or released guest security task")
			}
			var keyText string
			if keyObject != nil && keyObject.kind == guestCFStringType && keyObject.refs > 0 {
				keyText = keyObject.text
			} else if keyObject == nil {
				header, err := guest.engine.MemRead(key, 32)
				if err != nil {
					return err
				}
				class := binary.LittleEndian.Uint64(header)
				length := binary.LittleEndian.Uint64(header[24:])
				flags := binary.LittleEndian.Uint64(header[8:])
				if class != guest.symbols["___CFConstantStringClassReference"] || flags != 0x7c8 || length > guestMaxPathBytes {
					return fmt.Errorf("unsupported guest constant string class=%#x flags=%#x length=%d", class, flags, length)
				}
				data, err := guest.engine.MemRead(binary.LittleEndian.Uint64(header[16:]), length)
				if err != nil {
					return err
				}
				keyText = string(data)
			} else {
				return errors.New("unknown or released guest entitlement string")
			}
			if len(queries) >= 32 {
				return errors.New("excessive guest entitlement queries")
			}
			queries = append(queries, keyText)
			value, exists := values[keyText]
			if !exists {
				return guest.setResult(0)
			}
			handle, err := cf.newObject(guestCFBoolType, "", false)
			if err != nil {
				return err
			}
			if value {
				cf.objects[handle].data = []byte{1}
			} else {
				cf.objects[handle].data = []byte{0}
			}
			return guest.setResult(handle)
		},
		"_CFBooleanGetTypeID": func() error { return guest.setResult(guestCFBoolType) },
		"_CFBooleanGetValue": func() error {
			handle, err := guest.argument(0)
			if err != nil {
				return err
			}
			object := cf.objects[handle]
			if object == nil || object.kind != guestCFBoolType || object.refs == 0 || len(object.data) != 1 {
				return errors.New("unknown guest boolean")
			}
			return guest.setResult(uint64(object.data[0]))
		},
	} {
		if err := cf.replace(name, handler); err != nil {
			return nil, err
		}
	}
	return &queries, nil
}
