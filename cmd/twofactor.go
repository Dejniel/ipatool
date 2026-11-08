package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/majd/ipatool/v2/pkg/appstore"
)

func selectNumber(input io.Reader, output io.Writer, title string, labels []string) (int, error) {
	if _, err := fmt.Fprintln(output, title); err != nil {
		return -1, err
	}
	for i, label := range labels {
		if _, err := fmt.Fprintf(output, "  %d. %s\n", i+1, label); err != nil {
			return -1, err
		}
	}
	// Read a byte at a time: a buffered reader per prompt would consume input
	// intended for the following prompt when a caller supplies a pipe or file.
	for {
		if _, err := fmt.Fprint(output, "select a number (q to cancel): "); err != nil {
			return -1, err
		}
		var line strings.Builder
		for {
			var b [1]byte
			if _, err := io.ReadFull(input, b[:]); err != nil {
				return -1, fmt.Errorf("read 2FA selection: %w", err)
			}
			if b[0] == '\n' {
				break
			}
			if line.Len() >= 64 {
				return -1, errors.New("2FA selection is too long")
			}
			line.WriteByte(b[0])
		}
		text := strings.TrimSpace(line.String())
		if strings.EqualFold(text, "q") {
			return -1, errors.New("2FA selection cancelled")
		}
		number, err := strconv.Atoi(text)
		if err == nil && number > 0 && number <= len(labels) {
			return number - 1, nil
		}
		if _, err := fmt.Fprintln(output, "enter one of the listed numbers; no method was selected"); err != nil {
			return -1, err
		}
	}
}

func deliveryPrompts() *appstore.TwoFactorPrompts {
	return &appstore.TwoFactorPrompts{
		Select: func(methods []appstore.TwoFactorMethod) (int, error) {
			labels := make([]string, len(methods))
			for i, method := range methods {
				labels[i] = method.Label
			}
			return selectNumber(os.Stdin, os.Stderr, "Choose Apple 2FA delivery:", labels)
		},
		Code: func() (string, error) {
			return readPrompt("enter 2FA code for the selected destination: ", false)
		},
	}
}
