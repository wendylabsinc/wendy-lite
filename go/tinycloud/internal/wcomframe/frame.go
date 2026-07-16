// Package wcomframe implements the 8-byte WendyCom link-level frame header.
//
// The layout is defined by struct wcom_agent_msg_header in
// components/wendy_com/include/wendy_com_agent.h and is duplicated (not
// shared) with go/console/liteclient, which is kept self-contained for the
// WendyOS sync.
package wcomframe

import (
	"encoding/binary"
	"fmt"
)

const (
	Magic      = 0xA5
	Version    = 0x02
	HeaderSize = 8
	MaxBody    = 0xFFFF
)

// Header is the decoded form of the 8-byte frame header
// [magic][version][category][channel][reserved:2][body_size:2 BE].
type Header struct {
	Category uint8
	Channel  uint8
	BodyLen  uint16
}

// Encode returns header+body as a single frame.
func Encode(channel uint8, body []byte) ([]byte, error) {
	if len(body) > MaxBody {
		return nil, fmt.Errorf("body too large: %d > %d", len(body), MaxBody)
	}
	frame := make([]byte, HeaderSize+len(body))
	frame[0] = Magic
	frame[1] = Version
	frame[3] = channel
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(body)))
	copy(frame[HeaderSize:], body)
	return frame, nil
}

// DecodeHeader parses and validates the first HeaderSize bytes of b.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("short header: %d bytes", len(b))
	}
	if b[0] != Magic {
		return Header{}, fmt.Errorf("bad magic 0x%02x", b[0])
	}
	if b[1] != Version {
		return Header{}, fmt.Errorf("bad version 0x%02x", b[1])
	}
	return Header{
		Category: b[2],
		Channel:  b[3],
		BodyLen:  binary.BigEndian.Uint16(b[6:8]),
	}, nil
}
