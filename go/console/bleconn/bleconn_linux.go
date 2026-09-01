//go:build linux

package bleconn

// UNVERIFIED. This path has never been run against a device — the wendy_ble
// transport was developed and tested on macOS only. It is a direct port of the
// WendyOS CLI's L2CAP client, which is known to work against the WendyOS
// agent, but nothing here has been exercised against wendy-lite firmware.
//
// Two things are missing relative to macOS, both because BlueZ needs D-Bus for
// them and that dependency is not worth taking on until someone tests this:
//   - Scan is not implemented; pass an explicit Bluetooth address.
//   - ReadInfo is not implemented; the PSM falls back to DefaultPSM.

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Scan is not implemented on Linux: discovery needs BlueZ over D-Bus.
func Scan(timeout time.Duration) ([]Device, error) {
	return nil, fmt.Errorf("%w: scanning needs BlueZ over D-Bus; pass an explicit address (AA:BB:CC:DD:EE:FF)", ErrUnsupported)
}

// Conn is a live BLE connection to a device.
type Conn struct {
	fd   int
	addr [6]byte
}

// Dial parses the Bluetooth address and creates the L2CAP socket. The socket
// is not connected until OpenL2CAP, which is where the PSM is known.
func Dial(address string, timeout time.Duration) (*Conn, error) {
	addr, err := parseBTAddr(address)
	if err != nil {
		return nil, fmt.Errorf("parsing Bluetooth address: %w", err)
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, unix.BTPROTO_L2CAP)
	if err != nil {
		return nil, fmt.Errorf("creating L2CAP socket: %w", err)
	}
	return &Conn{fd: fd, addr: addr}, nil
}

// ReadInfo is not implemented on Linux: GATT needs BlueZ over D-Bus.
func (c *Conn) ReadInfo(timeout time.Duration) (*Info, error) {
	return nil, fmt.Errorf("%w: reading the GATT info service needs BlueZ over D-Bus", ErrUnsupported)
}

// OpenL2CAP connects the socket to the peer on the given PSM.
func (c *Conn) OpenL2CAP(psm uint16, timeout time.Duration) error {
	if err := unix.SetNonblock(c.fd, true); err != nil {
		return fmt.Errorf("set nonblocking: %w", err)
	}
	sa := &unix.SockaddrL2{
		PSM:      psm,
		Addr:     c.addr,
		AddrType: unix.BDADDR_LE_PUBLIC,
	}
	err := unix.Connect(c.fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		return fmt.Errorf("connecting L2CAP channel (PSM %d): %w", psm, err)
	}
	if err == unix.EINPROGRESS {
		pfd := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLOUT}}
		n, perr := unix.Poll(pfd, int(timeout.Milliseconds()))
		if perr != nil {
			return fmt.Errorf("waiting for L2CAP connect: %w", perr)
		}
		if n == 0 {
			return fmt.Errorf("L2CAP connect timed out after %s", timeout)
		}
		errno, serr := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if serr != nil {
			return fmt.Errorf("checking L2CAP connect result: %w", serr)
		}
		if errno != 0 {
			return fmt.Errorf("connecting L2CAP channel (PSM %d): %w", psm, unix.Errno(errno))
		}
	}
	return nil
}

func (c *Conn) send(b []byte) (int, error) {
	n, err := unix.Write(c.fd, b)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			// Wait for room rather than spinning; the channel is credit-based.
			pfd := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLOUT}}
			if _, perr := unix.Poll(pfd, int(recvSlice.Milliseconds())); perr != nil {
				return 0, perr
			}
			return 0, nil
		}
		return 0, err
	}
	return n, nil
}

func (c *Conn) recv(b []byte, timeout time.Duration) (int, error) {
	pfd := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, int(timeout.Milliseconds()))
	if err != nil {
		if err == unix.EINTR {
			return 0, nil
		}
		return 0, err
	}
	if n == 0 {
		return 0, nil // timeout; the caller re-checks its deadline
	}
	read, err := unix.Read(c.fd, b)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return 0, nil
		}
		return 0, err
	}
	if read == 0 {
		return 0, errClosed
	}
	return read, nil
}

// Close closes the L2CAP socket.
func (c *Conn) Close() error {
	if c.fd >= 0 {
		err := unix.Close(c.fd)
		c.fd = -1
		return err
	}
	return nil
}

// parseBTAddr turns "AA:BB:CC:DD:EE:FF" into the little-endian byte order the
// Bluetooth socket API expects (least significant byte first).
func parseBTAddr(s string) ([6]byte, error) {
	var addr [6]byte
	s = strings.ToUpper(s)
	if len(s) != 17 {
		return addr, fmt.Errorf("expected AA:BB:CC:DD:EE:FF, got %q", s)
	}
	for i, offset := range []int{15, 12, 9, 6, 3, 0} {
		if i > 0 && s[offset-1] != ':' {
			return addr, fmt.Errorf("bad separator at position %d in %q", offset-1, s)
		}
		var b byte
		if _, err := fmt.Sscanf(s[offset:offset+2], "%02X", &b); err != nil {
			return addr, fmt.Errorf("bad byte at position %d in %q: %w", offset, s, err)
		}
		addr[i] = b
	}
	return addr, nil
}
