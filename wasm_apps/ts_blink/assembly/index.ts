/**
 * Wendy MCU — AssemblyScript WASM Blink Demo
 *
 * Cycles through colors on the onboard NeoPixel (GPIO 8, ESP32-C6)
 * using the raw RMT timing-buffer API for precise WS2812 waveforms.
 *
 * Build with:
 *   npm install && npm run build
 */

// ── Wendy HAL imports ──────────────────────────────────────────────

@external("wendy", "rmt_configure")
declare function rmt_configure(pin: i32, resolution_hz: i32): i32;

@external("wendy", "rmt_transmit")
declare function rmt_transmit(channel_id: i32, buf: usize, len: i32): i32;

@external("wendy", "sys_sleep_ms")
declare function sys_sleep_ms(ms: i32): void;

// ── Static buffer for RMT symbols (25 × 4 = 100 bytes) ────────────

const buf: usize = memory.data(100);

// ── RMT symbol encoding ────────────────────────────────────────────

/** Pack one RMT symbol: two (level, duration) pairs into a u32. */
// @ts-ignore: decorator
@inline
function rmtSymbol(level0: u32, dur0: u32, level1: u32, dur1: u32): u32 {
  return (dur0 & 0x7FFF) | ((level0 & 1) << 15)
       | ((dur1 & 0x7FFF) << 16) | ((level1 & 1) << 31);
}

// WS2812 at 10 MHz: bit-1 = high 9 / low 3, bit-0 = high 3 / low 9
const BIT1: u32 = (9 & 0x7FFF) | ((1 & 1) << 15) | ((3 & 0x7FFF) << 16);
const BIT0: u32 = (3 & 0x7FFF) | ((1 & 1) << 15) | ((9 & 0x7FFF) << 16);

/** Encode one byte (MSB-first) into 8 RMT symbols at buffer offset. */
// @ts-ignore: decorator
@inline
function encodeByte(byte: u8, offset: i32): void {
  for (let i: i32 = 0; i < 8; i++) {
    store<u32>(buf + ((offset + i) << 2),
      ((byte >> (7 - i)) & 1) != 0 ? BIT1 : BIT0);
  }
}

/** Encode one GRB pixel and transmit via RMT. */
function ws2812Send(channel: i32, r: u8, g: u8, b: u8): void {
  // WS2812 expects GRB byte order
  encodeByte(g, 0);
  encodeByte(r, 8);
  encodeByte(b, 16);

  // Reset symbol: low for >50 us (500+500 ticks at 10 MHz = 100 us)
  store<u32>(buf + (24 << 2), rmtSymbol(0, 500, 0, 500));

  rmt_transmit(channel, buf, 25 * 4);
}

// ── Entry point ────────────────────────────────────────────────────

export function _start(): void {
  const channel = rmt_configure(8, 10_000_000); // 10 MHz
  if (channel < 0) return;

  while (true) {
    ws2812Send(channel, 255, 0,   0);     // red
    sys_sleep_ms(500);
    ws2812Send(channel, 0,   255, 0);     // green
    sys_sleep_ms(500);
    ws2812Send(channel, 0,   0,   255);   // blue
    sys_sleep_ms(500);
    ws2812Send(channel, 255, 255, 0);     // yellow
    sys_sleep_ms(500);
    ws2812Send(channel, 0,   255, 255);   // cyan
    sys_sleep_ms(500);
    ws2812Send(channel, 255, 0,   255);   // purple
    sys_sleep_ms(500);
    ws2812Send(channel, 255, 255, 255);   // white
    sys_sleep_ms(500);
    ws2812Send(channel, 0,   0,   0);     // off
    sys_sleep_ms(500);
  }
}
