package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestTwoFactorSelectionIsExplicit(t *testing.T) {
	for _, tc := range []struct {
		input  string
		index  int
		failed bool
	}{
		{"2\n", 1, false}, {"\n0\n3\ninvalid\n1\n", 0, false}, {"q\n", -1, true}, {"", -1, true},
	} {
		var out bytes.Buffer
		got, err := selectNumber(strings.NewReader(tc.input), &out, "Choose:", []string{"SMS ***12", "Phone call ***34"})
		if got != tc.index || (err != nil) != tc.failed {
			t.Fatalf("selection: %d, %v", got, err)
		}
		if !strings.Contains(out.String(), "2. Phone call ***34") {
			t.Fatal("missing second method")
		}
	}
	input := strings.NewReader("2\n123456\n")
	if _, err := selectNumber(input, io.Discard, "Choose:", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(input)
	if string(rest) != "123456\n" {
		t.Fatal("menu consumed code intended for next prompt")
	}
}
