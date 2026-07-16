package wcomframe

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	frame, err := Encode(42, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != HeaderSize+len(body) {
		t.Fatalf("frame length %d", len(frame))
	}
	h, err := DecodeHeader(frame)
	if err != nil {
		t.Fatal(err)
	}
	if h.Channel != 42 || h.Category != 0 || int(h.BodyLen) != len(body) {
		t.Fatalf("header %+v", h)
	}
	if !bytes.Equal(frame[HeaderSize:], body) {
		t.Fatal("body mismatch")
	}
}

func TestEncodeOversize(t *testing.T) {
	if _, err := Encode(1, make([]byte, MaxBody+1)); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := DecodeHeader([]byte{Magic, Version}); err == nil {
		t.Fatal("expected short-header error")
	}
	frame, _ := Encode(1, []byte{1})
	frame[0] = 0
	if _, err := DecodeHeader(frame); err == nil {
		t.Fatal("expected bad-magic error")
	}
	frame[0] = Magic
	frame[1] = 9
	if _, err := DecodeHeader(frame); err == nil {
		t.Fatal("expected bad-version error")
	}
}
