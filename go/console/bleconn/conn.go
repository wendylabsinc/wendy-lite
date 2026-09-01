//go:build darwin || linux

package bleconn

import (
	"errors"
	"io"
	"net"
	"time"
)

var errClosed = errors.New("BLE L2CAP: connection closed")

// recvSlice bounds how long a single platform read blocks. The read loop
// re-checks the caller's deadline between slices, so this only sets how
// quickly a deadline or a closed channel is noticed.
const recvSlice = 250 * time.Millisecond

// Stream presents the open L2CAP channel as a net.Conn, which is all
// crypto/tls and the WendyCom framing need. Call it after OpenL2CAP.
//
// The channel is a byte stream, not a datagram sequence: CoreBluetooth
// delivers it through an NSStream and drops SDU boundaries, so nothing above
// may assume one Read is one SDU.
func (c *Conn) Stream() net.Conn {
	return &stream{conn: c}
}

type stream struct {
	conn         *Conn
	readDeadline time.Time
}

func (s *stream) Read(b []byte) (int, error) {
	for {
		timeout := recvSlice
		if !s.readDeadline.IsZero() {
			remaining := time.Until(s.readDeadline)
			if remaining <= 0 {
				return 0, &timeoutError{}
			}
			if remaining < timeout {
				timeout = remaining
			}
		}

		n, err := s.conn.recv(b, timeout)
		if err != nil {
			if errors.Is(err, errClosed) {
				return 0, io.EOF
			}
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		// Nothing yet: loop, so a deadline is honoured to the slice.
	}
}

func (s *stream) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := s.conn.send(b[written:])
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, errClosed
		}
		written += n
	}
	return written, nil
}

func (s *stream) Close() error                     { return s.conn.Close() }
func (s *stream) LocalAddr() net.Addr              { return addr{} }
func (s *stream) RemoteAddr() net.Addr             { return addr{} }
func (s *stream) SetWriteDeadline(time.Time) error { return nil }

func (s *stream) SetDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

type addr struct{}

func (addr) Network() string { return "ble-l2cap" }
func (addr) String() string  { return "ble" }

type timeoutError struct{}

func (*timeoutError) Error() string   { return "BLE L2CAP: i/o timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }
