//go:build !darwin && !linux

package bleconn

import (
	"net"
	"time"
)

// Scan is unavailable: no BLE client exists for this platform.
func Scan(timeout time.Duration) ([]Device, error) { return nil, ErrUnsupported }

// Conn is a placeholder so callers compile everywhere; every method fails.
type Conn struct{}

// Dial is unavailable: no BLE client exists for this platform.
func Dial(address string, timeout time.Duration) (*Conn, error) { return nil, ErrUnsupported }

func (c *Conn) ReadInfo(timeout time.Duration) (*Info, error)     { return nil, ErrUnsupported }
func (c *Conn) OpenL2CAP(psm uint16, timeout time.Duration) error { return ErrUnsupported }
func (c *Conn) Stream() net.Conn                                  { return nil }
func (c *Conn) Close() error                                      { return nil }
