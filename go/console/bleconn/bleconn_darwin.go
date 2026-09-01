//go:build darwin

package bleconn

/*
#cgo CFLAGS: -fobjc-arc -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreBluetooth -framework Foundation
#include <stdlib.h>
#include "bleconn_darwin.h"
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

const maxScanResults = 16

// Scan looks for wendy-lite peripherals for the given duration.
func Scan(timeout time.Duration) ([]Device, error) {
	items := make([]C.wble_scan_item, maxScanResults)
	var cerr C.wble_err
	n := C.wble_scan(C.int(timeout.Milliseconds()), &items[0],
		C.int(maxScanResults), &cerr)
	if n < 0 {
		return nil, bleError(cerr, "scanning")
	}

	devices := make([]Device, 0, int(n))
	for i := 0; i < int(n); i++ {
		devices = append(devices, Device{
			Address: C.GoString(&items[i].identifier[0]),
			Name:    C.GoString(&items[i].local_name[0]),
			ID:      C.GoString(&items[i].device_id[0]),
			RSSI:    int(items[i].rssi),
		})
	}
	return devices, nil
}

// Conn is a live BLE connection to a device. It becomes a byte stream once
// OpenL2CAP succeeds; use Stream to get the net.Conn.
type Conn struct {
	handle C.wble_conn
}

// Dial connects to the peripheral at address. It does not open the L2CAP
// channel — call ReadInfo and OpenL2CAP next.
func Dial(address string, timeout time.Duration) (*Conn, error) {
	cAddr := C.CString(address)
	defer C.free(unsafe.Pointer(cAddr))

	var cerr C.wble_err
	h := C.wble_connect(cAddr, C.int(timeout.Milliseconds()), &cerr)
	if h == nil {
		return nil, bleError(cerr, fmt.Sprintf("connecting to %s", address))
	}
	return &Conn{handle: h}, nil
}

// ReadInfo reads the device's GATT info service, which carries the PSM to
// open along with the identity the device advertises for itself.
func (c *Conn) ReadInfo(timeout time.Duration) (*Info, error) {
	var (
		psm     C.uint16_t
		mtls    C.uint8_t
		devID   [C.WBLE_STR_CAP]C.char
		devName [C.WBLE_STR_CAP]C.char
		display [C.WBLE_STR_CAP]C.char
	)
	cerr := C.wble_read_info(c.handle, C.int(timeout.Milliseconds()),
		&psm, &mtls, &devID[0], &devName[0], &display[0])
	if cerr != C.WBLE_OK {
		return nil, bleError(cerr, "reading device info")
	}
	return &Info{
		PSM:         uint16(psm),
		DeviceID:    C.GoString(&devID[0]),
		DeviceName:  C.GoString(&devName[0]),
		DisplayName: C.GoString(&display[0]),
		MTLSEnabled: mtls != 0,
	}, nil
}

// OpenL2CAP opens the connection-oriented channel that carries the stream.
func (c *Conn) OpenL2CAP(psm uint16, timeout time.Duration) error {
	cerr := C.wble_open_l2cap(c.handle, C.uint16_t(psm),
		C.int(timeout.Milliseconds()))
	if cerr != C.WBLE_OK {
		return bleError(cerr, fmt.Sprintf("opening L2CAP channel (PSM %d)", psm))
	}
	return nil
}

// send writes to the channel. CoreBluetooth may accept fewer bytes than
// offered, so the count is what the caller must loop on.
func (c *Conn) send(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n := C.wble_send(c.handle, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.int(len(b)))
	if n < 0 {
		return 0, fmt.Errorf("BLE L2CAP write failed")
	}
	return int(n), nil
}

// recv reads from the channel. It returns (0, nil) on timeout so the caller
// can decide whether its deadline has expired.
func (c *Conn) recv(b []byte, timeout time.Duration) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	ms := timeout.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	n := C.wble_recv(c.handle, (*C.uint8_t)(unsafe.Pointer(&b[0])),
		C.int(len(b)), C.int(ms))
	if n < 0 {
		return 0, errClosed
	}
	return int(n), nil
}

// Close disconnects and releases every BLE resource.
func (c *Conn) Close() error {
	if c.handle != nil {
		C.wble_close(c.handle)
		c.handle = nil
	}
	return nil
}

func bleError(code C.wble_err, context string) error {
	var msg string
	switch code {
	case C.WBLE_ERR_TIMEOUT:
		msg = "timeout"
	case C.WBLE_ERR_NOT_FOUND:
		msg = "not found"
	case C.WBLE_ERR_CONNECT:
		msg = "connection failed"
	case C.WBLE_ERR_DISCOVER:
		msg = "the device does not expose the wendy-lite info service"
	case C.WBLE_ERR_READ:
		msg = "read failed"
	case C.WBLE_ERR_L2CAP:
		msg = "L2CAP channel failed"
	case C.WBLE_ERR_DISCONNECTED:
		msg = "disconnected"
	case C.WBLE_ERR_UNAUTHORIZED:
		msg = "Bluetooth permission denied — grant it in System Settings > Privacy & Security > Bluetooth"
	case C.WBLE_ERR_POWERED_OFF:
		msg = "Bluetooth is turned off"
	default:
		msg = "unknown error"
	}
	return fmt.Errorf("BLE %s: %s", context, msg)
}
