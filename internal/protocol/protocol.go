// Package protocol implements the stdin/stdout wire protocol between the
// pam_authelia Go binary and its C PAM shim.
package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	cmdPromptHidden       = "PROMPT_HIDDEN:"
	cmdPromptVisible      = "PROMPT_VISIBLE:"
	cmdPromptMultiVisible = "PROMPT_MULTI_VISIBLE:"
	cmdInfo               = "INFO:"
	cmdSuccess            = "SUCCESS"
	cmdFailure            = "FAILURE:"
)

// MaxLineLength caps ReadLine to prevent unbounded allocation from a malformed
// sender. The shim's own MAX_LINE is 4096, so 64 KiB leaves generous headroom.
const MaxLineLength = 64 * 1024

// ErrLineTooLong is returned by ReadLine when a line exceeds MaxLineLength.
var ErrLineTooLong = errors.New("protocol: line exceeds maximum length")

// WritePromptHidden sends a hidden-input prompt to the C shim via PAM_PROMPT_ECHO_OFF.
func WritePromptHidden(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, "%s%s\n", cmdPromptHidden, text)
	return err
}

// WritePromptVisible sends a visible-input prompt to the C shim via PAM_PROMPT_ECHO_ON.
func WritePromptVisible(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, "%s%s\n", cmdPromptVisible, text)
	return err
}

// WritePromptMultiVisible sends a length-prefixed multi-line prompt dispatched
// via PAM_PROMPT_ECHO_ON. Used for payloads with embedded newlines (e.g. a QR)
// that need the unsanitised RFC 4256 prompt field on BSD ssh clients.
func WritePromptMultiVisible(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, "%s%d\n%s", cmdPromptMultiVisible, len(text), text)
	return err
}

// WriteInfo sends an informational message to the C shim via PAM_TEXT_INFO.
func WriteInfo(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, "%s%s\n", cmdInfo, text)
	return err
}

// WriteSuccess signals successful authentication to the C shim.
func WriteSuccess(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s\n", cmdSuccess)
	return err
}

// WriteFailure signals failed authentication to the C shim with a reason.
func WriteFailure(w io.Writer, message string) error {
	_, err := fmt.Fprintf(w, "%s%s\n", cmdFailure, message)
	return err
}

// ReadLine reads a single line from the reader, trimming the trailing newline.
// Input is bounded at MaxLineLength; exceeding it returns ErrLineTooLong.
func ReadLine(r *bufio.Reader) (string, error) {
	var buf strings.Builder

	for {
		if buf.Len() >= MaxLineLength {
			return "", ErrLineTooLong
		}

		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF && buf.Len() > 0 {
				return strings.TrimRight(buf.String(), "\r\n"), nil
			}

			return "", err
		}

		if b == '\n' {
			return strings.TrimRight(buf.String(), "\r"), nil
		}

		buf.WriteByte(b)
	}
}
