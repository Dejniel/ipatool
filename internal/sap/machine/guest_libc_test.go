package machine

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestGuestScanVersion(t *testing.T) {
	for _, test := range []struct {
		input  string
		values []uint64
		count  int32
	}{
		{"27.0.1", []uint64{27, 0, 1}, 3},
		{"13.5.2 trailing", []uint64{13, 5, 2}, 3},
		{" \t+27.\n0.01", []uint64{27, 0, 1}, 3},
		{"-1.0.0", []uint64{math.MaxUint64, 0, 0}, 3},
		{"18446744073709551615.0.1", []uint64{math.MaxUint64, 0, 1}, 3},
		{"27.0", []uint64{27, 0}, 2},
		{"27.x.1", []uint64{27}, 1},
		{"27 .0.1", []uint64{27}, 1},
		{"27.", []uint64{27}, 1},
		{"no-version", nil, 0},
		{"", nil, -1},
		{" \t", nil, -1},
	} {
		t.Run(test.input, func(t *testing.T) {
			values, count, err := guestScanVersion(test.input)
			if err != nil || count != test.count || !reflect.DeepEqual(values, test.values) {
				t.Fatalf("got %v, %d, %v; want %v, %d", values, count, err, test.values, test.count)
			}
		})
	}
	if _, _, err := guestScanVersion("18446744073709551616.0.1"); err == nil {
		t.Fatal("overflow was silently converted")
	}
}

func guestScanf(t *testing.T, guest *Machine, input, format string, outputs ...uint64) (uint64, error) {
	t.Helper()
	const inputAddress = scratchBase
	const formatAddress = scratchBase + 0x2000
	if err := guest.engine.MemWrite(inputAddress, append([]byte(input), 0)); err != nil {
		t.Fatal(err)
	}
	if err := guest.engine.MemWrite(formatAddress, append([]byte(format), 0)); err != nil {
		t.Fatal(err)
	}
	arguments := []uint64{inputAddress, formatAddress, 0xdead, 0xdead, 0xdead, 0xdead, 0xdead, 0xdead}
	return guest.invoke(guest.services.symbols["_sscanf"], append(arguments, outputs...)...)
}

func TestGuestScanfDarwinStackArguments(t *testing.T) {
	guest := newServiceTestMachine(t)
	if err := installGuestLibc(guest.services); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x4000
	value, err := guestScanf(t, guest, "27.0.1", "%llu.%llu.%llu", output, output+8, output+16)
	if err != nil || value != 3 {
		t.Fatalf("sscanf result = %d, %v", value, err)
	}
	for index, want := range []uint64{27, 0, 1} {
		got, err := guest.services.readUint64(output + uint64(index)*8)
		if err != nil || got != want {
			t.Fatalf("output %d = %d, %v; want %d", index, got, err, want)
		}
	}
}

func TestGuestScanfPartialConversionAndFailures(t *testing.T) {
	guest := newServiceTestMachine(t)
	if err := installGuestLibc(guest.services); err != nil {
		t.Fatal(err)
	}
	const output = scratchBase + 0x4000
	sentinel := bytes.Repeat([]byte{0xa5}, 24)
	if err := guest.engine.MemWrite(output, sentinel); err != nil {
		t.Fatal(err)
	}
	value, err := guestScanf(t, guest, "13.x", "%llu.%llu.%llu", output, output+8, output+16)
	if err != nil || value != 1 {
		t.Fatalf("partial result = %d, %v", value, err)
	}
	data, err := guest.engine.MemRead(output, 24)
	if err != nil || binary.LittleEndian.Uint64(data) != 13 || !bytes.Equal(data[8:], sentinel[8:]) {
		t.Fatal("partial conversion modified unmatched outputs")
	}
	if _, err := guestScanf(t, guest, "27.0.1", "%n", output); err == nil {
		t.Fatal("unsupported format accepted")
	}
	if _, err := guestScanf(t, guest, "27.0.1", "%llu.%llu.%llu", 0, output+8, output+16); err == nil {
		t.Fatal("null output accepted")
	}
	if _, err := guestScanf(t, guest, "27.0.1", "%llu.%llu.%llu", 0xdead, output+8, output+16); err == nil {
		t.Fatal("unmapped output accepted")
	}
}

func TestGuestScanfRequiresExplicitInstallation(t *testing.T) {
	guest := newServiceTestMachine(t)
	address, err := guest.services.resolve("_sscanf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guest.invoke(address); err == nil {
		t.Fatal("uninstalled sscanf provider was active")
	}
}

func TestGuestUmaskIsGuestLocal(t *testing.T) {
	for index := 0; index < 2; index++ {
		guest := newServiceTestMachine(t)
		if _, err := installGuestFiles(guest.services); err != nil {
			t.Fatal(err)
		}
		if got := guestCFCall(t, guest, "_umask", 0077); got != 0022 {
			t.Fatalf("initial mask = %o", got)
		}
		if got := guestCFCall(t, guest, "_umask", 01777); got != 0077 {
			t.Fatalf("previous mask = %o", got)
		}
		if got := guestCFCall(t, guest, "_umask", 0022); got != 0777 {
			t.Fatalf("permission mask = %o", got)
		}
	}
}
