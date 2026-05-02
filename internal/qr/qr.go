// Package qr renders QR codes as Unicode half-block text suitable for terminal display.
package qr

import (
	"fmt"
	"image/color"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

const (
	fullBlock  = "█"
	upperHalf  = "▀"
	lowerHalf  = "▄"
	emptyBlock = " "
)

// Render encodes payload as a Unicode half-block QR code with a one-module quiet
// zone, suitable for terminal display.
func Render(payload string) (string, error) {
	code, err := qr.Encode(payload, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	size := code.Bounds().Max.X

	const quiet = 1

	var b strings.Builder

	for y := -quiet; y < size+quiet; y += 2 {
		for x := -quiet; x < size+quiet; x++ {
			top := moduleOn(code, x, y, size)
			bot := moduleOn(code, x, y+1, size)

			switch {
			case top && bot:
				b.WriteString(fullBlock)
			case top:
				b.WriteString(upperHalf)
			case bot:
				b.WriteString(lowerHalf)
			default:
				b.WriteString(emptyBlock)
			}
		}

		b.WriteByte('\n')
	}

	return b.String(), nil
}

func moduleOn(code barcode.Barcode, x, y, size int) bool {
	if x < 0 || y < 0 || x >= size || y >= size {
		return false
	}

	return code.At(x, y) == color.Black
}
