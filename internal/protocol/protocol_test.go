package protocol

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWritePromptHidden(t *testing.T) {
	var buf bytes.Buffer

	err := WritePromptHidden(&buf, "Password: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "PROMPT_HIDDEN:Password: \n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestWritePromptVisible(t *testing.T) {
	var buf bytes.Buffer

	err := WritePromptVisible(&buf, "TOTP Code: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "PROMPT_VISIBLE:TOTP Code: \n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestWriteInfo(t *testing.T) {
	var buf bytes.Buffer

	err := WriteInfo(&buf, "Duo Push sent, approve on your device.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "INFO:Duo Push sent, approve on your device.\n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestWriteSuccess(t *testing.T) {
	var buf bytes.Buffer

	err := WriteSuccess(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "SUCCESS\n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestWriteFailure(t *testing.T) {
	var buf bytes.Buffer

	err := WriteFailure(&buf, "authentication failed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "FAILURE:authentication failed\n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestWritePromptMultiVisible(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"Empty", ""},
		{"SingleLine", "hello"},
		{"Multiline", "line one\nline two\nline three"},
		{"TrailingNewlines", "body\n\n"},
		{"BinaryIsh", "bytes\x00\x01\x02\xff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			if err := WritePromptMultiVisible(&buf, tt.text); err != nil {
				t.Fatalf("WritePromptMultiVisible(%q) error = %v", tt.name, err)
			}

			expected := "PROMPT_MULTI_VISIBLE:" + fmt.Sprintf("%d", len(tt.text)) + "\n" + tt.text
			if buf.String() != expected {
				t.Errorf("got %q, want %q", buf.String(), expected)
			}
		})
	}
}

func TestReadLineLengthCap(t *testing.T) {
	// Build a line that exceeds MaxLineLength and lacks a newline.
	oversized := strings.Repeat("A", MaxLineLength+10) + "\n"
	reader := bufio.NewReader(bytes.NewBufferString(oversized))

	_, err := ReadLine(reader)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("expected ErrLineTooLong, got %v", err)
	}
}

func TestReadLineAtMaxLength(t *testing.T) {
	// A line of exactly MaxLineLength followed by \n should be returned (since we
	// check `>= MaxLineLength` before reading each byte, MaxLineLength chars plus
	// the terminator fits exactly).
	line := strings.Repeat("B", MaxLineLength-1) + "\n"
	reader := bufio.NewReader(bytes.NewBufferString(line))

	got, err := ReadLine(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != MaxLineLength-1 {
		t.Errorf("got len %d, want %d", len(got), MaxLineLength-1)
	}
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple", "hello\n", "hello", false},
		{"with carriage return", "hello\r\n", "hello", false},
		{"empty line", "\n", "", false},
		{"no newline EOF", "", "", true},
		{"username", "jdoe\n", "jdoe", false},
		{"password with special chars", "p@ss:w0rd!\n", "p@ss:w0rd!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(bytes.NewBufferString(tt.input))

			got, err := ReadLine(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("ReadLine() = %q, want %q", got, tt.want)
			}
		})
	}
}
