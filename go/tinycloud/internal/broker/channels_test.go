package broker

import (
	"testing"
	"time"
)

func TestAllocateNeverZero(t *testing.T) {
	a := newChannelAllocator()
	for i := 0; i < 255; i++ {
		ch, err := a.allocate()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		if ch == 0 {
			t.Fatal("allocated channel 0")
		}
	}
	if _, err := a.allocate(); err != ErrNoFreeChannel {
		t.Fatalf("expected exhaustion, got %v", err)
	}
}

func TestQuarantineBlocksReuse(t *testing.T) {
	a := newChannelAllocator()
	// exhaust the space so a re-allocation must consider the released id
	seen := make(map[uint8]bool)
	for i := 0; i < 255; i++ {
		ch, _ := a.allocate()
		seen[ch] = true
	}
	if len(seen) != 255 {
		t.Fatalf("expected 255 distinct ids, got %d", len(seen))
	}
	a.release(7)
	if _, err := a.allocate(); err != ErrNoFreeChannel {
		t.Fatalf("quarantined id was reused: %v", err)
	}
	// expire the quarantine manually
	a.mu.Lock()
	a.freeAt[7] = time.Now().Add(-time.Second)
	a.mu.Unlock()
	ch, err := a.allocate()
	if err != nil || ch != 7 {
		t.Fatalf("expected id 7 after quarantine, got %d, %v", ch, err)
	}
}

func TestRotationCursor(t *testing.T) {
	a := newChannelAllocator()
	a.quarantine = 0
	ch1, _ := a.allocate()
	a.release(ch1)
	a.mu.Lock()
	a.freeAt[ch1] = time.Now().Add(-time.Second)
	a.mu.Unlock()
	ch2, _ := a.allocate()
	if ch1 == ch2 {
		t.Fatalf("cursor did not rotate: %d reused immediately", ch1)
	}
}
