package broker

import (
	"errors"
	"sync"
	"time"
)

const quarantinePeriod = time.Minute

var ErrNoFreeChannel = errors.New("no free channel id")

// channelAllocator hands out channel ids 1..255 (0 is the implicit default
// channel and is never allocated). A released id is quarantined for
// quarantinePeriod before it can be reused, so a late frame from the device
// cannot land on a channel's new owner.
type channelAllocator struct {
	mu         sync.Mutex
	inUse      map[uint8]bool
	freeAt     map[uint8]time.Time // quarantined until this instant
	next       uint8               // rotation cursor: avoids immediate reuse even past quarantine
	quarantine time.Duration
}

func newChannelAllocator() *channelAllocator {
	return &channelAllocator{
		inUse:      make(map[uint8]bool),
		freeAt:     make(map[uint8]time.Time),
		quarantine: quarantinePeriod,
	}
}

func (a *channelAllocator) allocate() (uint8, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	ch := a.next
	for i := 0; i < 255; i++ {
		ch++
		if ch == 0 {
			ch = 1
		}
		if a.inUse[ch] {
			continue
		}
		if until, quarantined := a.freeAt[ch]; quarantined {
			if now.Before(until) {
				continue
			}
			delete(a.freeAt, ch) // quarantine expired
		}
		a.inUse[ch] = true
		a.next = ch
		return ch, nil
	}
	return 0, ErrNoFreeChannel
}

func (a *channelAllocator) release(ch uint8) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.inUse, ch)
	a.freeAt[ch] = time.Now().Add(a.quarantine)
}
