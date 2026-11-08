package machine

import (
	"errors"
	"strconv"
	"strings"
)

func installGuestLibc(guest *shims) error {
	address, err := guest.resolve("_sscanf")
	if err != nil {
		return err
	}
	guest.entries[address] = shimEntry{name: "_sscanf", handler: func() error {
		inputPointer, err := guest.argument(0)
		if err != nil {
			return err
		}
		formatPointer, err := guest.argument(1)
		if err != nil {
			return err
		}
		input, err := guest.readCString(inputPointer)
		if err != nil {
			return err
		}
		format, err := guest.readCString(formatPointer)
		if err != nil {
			return err
		}
		if format != "%llu.%llu.%llu" {
			return errors.New("unsupported guest sscanf format")
		}
		values, count, err := guestScanVersion(input)
		if err != nil {
			return err
		}
		for index, value := range values {
			// Darwin ARM64 passes unnamed variadic arguments on the stack.
			pointer, err := guest.argument(8 + index)
			if err != nil {
				return err
			}
			if pointer == 0 {
				return errors.New("guest sscanf destination is null")
			}
			if err := guest.writeUint64(pointer, value); err != nil {
				return err
			}
		}
		return guest.setResult(uint64(int64(count)))
	}}
	return nil
}

// Only the traced unsigned decimal version format is supported. Other formats
// and out-of-range conversions stop the guest rather than inventing a result.
func guestScanVersion(input string) ([]uint64, int32, error) {
	var values []uint64
	for index := 0; index < 3; index++ {
		if index != 0 {
			if !strings.HasPrefix(input, ".") {
				break
			}
			input = input[1:]
		}
		input = strings.TrimLeft(input, " \t\n\r\v\f")
		if input == "" {
			if len(values) == 0 {
				return nil, -1, nil
			}
			break
		}
		negative := input[0] == '-'
		if input[0] == '+' || negative {
			input = input[1:]
		}
		length := 0
		for length < len(input) && input[length] >= '0' && input[length] <= '9' {
			length++
		}
		if length == 0 {
			break
		}
		value, err := strconv.ParseUint(input[:length], 10, 64)
		if err != nil {
			return nil, 0, errors.New("guest sscanf conversion exceeds uint64")
		}
		if negative {
			value = 0 - value
		}
		values = append(values, value)
		input = input[length:]
	}
	return values, int32(len(values)), nil
}
