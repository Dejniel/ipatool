package unicorn

import (
	"context"
	"testing"
)

func TestGuestCPUContextPreservesScalarAndVectorState(t *testing.T) {
	engine, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	want := [16]byte{1, 4, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59}
	if err := engine.RegWrite(RegX0, 0x12345678); err != nil {
		t.Fatal(err)
	}
	if err := engine.RegWrite128(RegV0, want); err != nil {
		t.Fatal(err)
	}
	state, err := engine.SaveCPU()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Clear()
	if err := engine.RegWrite(RegX0, 0); err != nil {
		t.Fatal(err)
	}
	if err := engine.RegWrite128(RegV0, [16]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := engine.RestoreCPU(state); err != nil {
		t.Fatal(err)
	}
	scalar, err := engine.RegRead(RegX0)
	if err != nil || scalar != 0x12345678 {
		t.Fatal("scalar register not restored")
	}
	vector, err := engine.RegRead128(RegV0)
	if err != nil || vector != want {
		t.Fatal("vector register not restored")
	}
	other, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.RestoreCPU(state); err == nil {
		t.Fatal("another engine accepted this context")
	}
	state.Clear()
	if err := engine.RestoreCPU(state); err == nil {
		t.Fatal("cleared context accepted")
	}
}
