package machine

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestGuestTaskEntitlementsMatchOnlyDeclaredCaller(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	audit := bytes.Repeat([]byte{0x11}, 32)
	values := map[string]bool{"present": true, "disabled": false}
	queries, err := installGuestTaskEntitlements(cf, audit, values)
	if err != nil {
		t.Fatal(err)
	}
	values["absent"] = true
	if err := guest.engine.MemWrite(scratchBase, audit); err != nil {
		t.Fatal(err)
	}
	clear(audit)
	task := guestCFCall(t, guest, "_SecTaskCreateWithAuditToken", 0, scratchBase)
	for _, name := range []string{"present", "disabled", "absent"} {
		key, err := cf.newObject(guestCFStringType, name, false)
		if err != nil {
			t.Fatal(err)
		}
		const errorOutput = scratchBase + 0x100
		if err := guest.services.writeUint64(errorOutput, 0); err != nil {
			t.Fatal(err)
		}
		value := guestCFCall(t, guest, "_SecTaskCopyValueForEntitlement", task, key, errorOutput)
		if name == "absent" {
			if value != 0 {
				t.Fatal("missing entitlement was fabricated")
			}
			continue
		}
		if guestCFCall(t, guest, "_CFGetTypeID", value) != guestCFCall(t, guest, "_CFBooleanGetTypeID") {
			t.Fatal("entitlement is not a CFBoolean")
		}
		want := uint64(0)
		if name == "present" {
			want = 1
		}
		if guestCFCall(t, guest, "_CFBooleanGetValue", value) != want {
			t.Fatal("entitlement value changed")
		}
		guestCFCall(t, guest, "_CFRelease", value)
		if _, err := guest.invoke(guest.services.symbols["_CFBooleanGetValue"], value); err == nil {
			t.Fatal("released boolean accepted")
		}
	}
	if len(*queries) != 3 {
		t.Fatal("entitlement queries not recorded")
	}
	if err := guest.engine.MemWrite(scratchBase, audit); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_SecTaskCreateWithAuditToken"], 0, scratchBase); err == nil {
		t.Fatal("unregistered caller accepted")
	}
	guestCFCall(t, guest, "_CFRelease", task)
	if _, err := guest.invoke(guest.services.symbols["_SecTaskCopyValueForEntitlement"], task, 0, 0); err == nil {
		t.Fatal("released task accepted")
	}
}

func TestGuestTaskAuditFieldsUseDarwinArguments(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	for index := 0; index < 8; index++ {
		binary.LittleEndian.PutUint32(token[index*4:], uint32(index+101))
	}
	if _, err := installGuestTaskEntitlements(cf, token, nil); err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(scratchBase, token); err != nil {
		t.Fatal(err)
	}
	arguments := []uint64{scratchBase}
	for index := uint64(0); index < 7; index++ {
		arguments = append(arguments, scratchBase+0x100+index*4)
	}
	arguments = append(arguments, 0)
	guestCFCall(t, guest, "_audit_token_to_au32", arguments...)
	fields, err := guest.engine.MemRead(scratchBase+0x100, 28)
	if err != nil || !bytes.Equal(fields, token[:28]) {
		t.Fatal("audit fields changed")
	}
	arguments[8] = scratchBase + 0x200
	if _, err := guest.invoke(guest.services.symbols["_audit_token_to_au32"], arguments...); err == nil {
		t.Fatal("unsupported terminal identity accepted")
	}
}

func TestGuestTaskReadsConstantAndOwnedEntitlementNames(t *testing.T) {
	guest := newServiceTestMachine(t)
	cf, err := installGuestCFURL(guest.services, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := make([]byte, 32)
	if _, err := installGuestTaskEntitlements(cf, token, map[string]bool{"declared": true}); err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(scratchBase, token); err != nil {
		t.Fatal(err)
	}
	task := guestCFCall(t, guest, "_SecTaskCreateWithAuditToken", 0, scratchBase)
	const text = scratchBase + 0x100
	if err := guest.engine.MemWrite(text, []byte("declared\x00")); err != nil {
		t.Fatal(err)
	}
	owned := guestCFCall(t, guest, "_CFStringCreateWithCStringNoCopy", 0, text, 0x600, 0)
	value := guestCFCall(t, guest, "_SecTaskCopyValueForEntitlement", task, owned, 0)
	if guestCFCall(t, guest, "_CFBooleanGetValue", value) != 1 {
		t.Fatal("ASCII entitlement name changed")
	}
	class, err := guest.services.resolve("___CFConstantStringClassReference")
	if err != nil {
		t.Fatal(err)
	}
	constant := make([]byte, 32)
	binary.LittleEndian.PutUint64(constant, class)
	binary.LittleEndian.PutUint64(constant[8:], 0x7c8)
	binary.LittleEndian.PutUint64(constant[16:], text)
	binary.LittleEndian.PutUint64(constant[24:], 8)
	const key = scratchBase + 0x200
	if err := guest.engine.MemWrite(key, constant); err != nil {
		t.Fatal(err)
	}
	value = guestCFCall(t, guest, "_SecTaskCopyValueForEntitlement", task, key, 0)
	if guestCFCall(t, guest, "_CFBooleanGetValue", value) != 1 {
		t.Fatal("constant entitlement name changed")
	}
	if err := guest.services.writeUint64(key+8, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(guest.services.symbols["_SecTaskCopyValueForEntitlement"], task, key, 0); err == nil {
		t.Fatal("unknown constant string layout accepted")
	}
	if _, err := guest.invoke(guest.services.symbols["_CFStringCreateWithCStringNoCopy"], 0, text, 0x100, 0); err == nil {
		t.Fatal("unsupported caller encoding accepted")
	}
}
