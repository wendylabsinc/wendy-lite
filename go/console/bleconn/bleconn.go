// Package bleconn dials a wendy-lite device over BLE and hands back a
// net.Conn carrying the raw L2CAP byte stream. Everything above it — TLS, the
// WendyCom framing, the session — is transport-agnostic and lives in
// liteclient.
//
// The device is the peripheral: it advertises the wendy-lite service UUID and
// listens on an L2CAP connection-oriented channel. See
// components/wendy_ble/src/wendy_ble.c for the other end.
package bleconn

import "errors"

// DefaultPSM is the L2CAP PSM the device listens on, mirroring
// CONFIG_WENDY_BLE_PSM. It is only a fallback: where GATT reads are available
// the PSM comes from the device's info service instead.
const DefaultPSM = 128

// ServiceUUID is the wendy-lite BLE info service. Devices advertise it so a
// scan can filter in-stack.
const ServiceUUID = "4E57454E-4459-0002-0000-000000000000"

// ErrUnsupported is returned on platforms with no BLE client implementation.
var ErrUnsupported = errors.New("BLE is not supported on this platform")

// Device is one peripheral seen during a scan.
type Device struct {
	// Address identifies the peripheral to Dial. On macOS it is a per-host
	// CoreBluetooth UUID (not stable across machines); on Linux it is a
	// Bluetooth address.
	Address string

	// Name is the advertised local name. It comes from the scan response, so
	// it can be empty if only the first advertising report was seen.
	Name string

	// ID is the device ID from the advertisement's manufacturer data. It is
	// what the WendyCom identity command reports as the device id.
	ID string

	RSSI int
}

// Info is the content of the device's GATT info service. It is what the
// device publishes about itself before any TLS work happens, so it is
// untrusted: treat it as a label for picking a device, never as proof of
// identity. The mTLS handshake is what authenticates.
type Info struct {
	PSM         uint16
	DeviceID    string
	DeviceName  string
	DisplayName string
	MTLSEnabled bool
}
