// Package broker bridges gRPC tunnel clients and reverse-connected devices,
// multiplexing tunnels onto a device link via the frame header channel byte.
package broker

import (
	"log"
	"net"
	"sync"
)

// Until the asset id is read from the device's mTLS client certificate,
// every device connection is registered under this id.
const hardcodedAssetID = "00000000-0000-0000-0000-000000000023"

type Broker struct {
	mu      sync.Mutex
	devices map[string]*deviceConn
}

func New() *Broker {
	return &Broker{devices: make(map[string]*deviceConn)}
}

// ServeDevices accepts reverse device connections on ln forever.
func (b *Broker) ServeDevices(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("device accept: %v", err)
			return
		}
		d := b.registerDevice(conn)
		log.Printf("device %s connected from %s", d.assetID, conn.RemoteAddr())
		go d.readLoop()
	}
}

func (b *Broker) registerDevice(conn net.Conn) *deviceConn {
	d := &deviceConn{
		assetID: hardcodedAssetID,
		conn:    conn,
		broker:  b,
		alloc:   newChannelAllocator(),
		tunnels: make(map[uint8]*tunnel),
	}
	b.mu.Lock()
	old := b.devices[d.assetID]
	b.devices[d.assetID] = d
	b.mu.Unlock()
	if old != nil {
		log.Printf("device %s reconnected, dropping previous connection", d.assetID)
		old.shutdown()
	}
	return d
}

func (b *Broker) device(assetID string) *deviceConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.devices[assetID]
}

// dropDevice removes d from the registry unless it was already replaced.
func (b *Broker) dropDevice(d *deviceConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.devices[d.assetID] == d {
		delete(b.devices, d.assetID)
	}
}
