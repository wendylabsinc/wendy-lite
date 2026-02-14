/**
 * Wendy MCU — Example WASM Application: Blink
 *
 * This program runs inside the WAMR runtime on the ESP32.
 * It imports HAL functions from the "wendy" module to control GPIO.
 *
 * Build with:
 *   clang --target=wasm32 -O2 -nostdlib \
 *     -Wl,--no-entry -Wl,--export=_start \
 *     -Wl,--allow-undefined \
 *     -o blink.wasm blink.c
 */

/* ── Wendy HAL imports (provided by the firmware) ──────────────────── */

__attribute__((import_module("wendy"), import_name("gpio_configure")))
int gpio_configure(int pin, int mode, int pull);

__attribute__((import_module("wendy"), import_name("gpio_write")))
int gpio_write(int pin, int level);

__attribute__((import_module("wendy"), import_name("gpio_read")))
int gpio_read(int pin);

__attribute__((import_module("wendy"), import_name("timer_delay_ms")))
void timer_delay_ms(int ms);

__attribute__((import_module("wendy"), import_name("timer_millis")))
long long timer_millis(void);

__attribute__((import_module("wendy"), import_name("wendy_print")))
int wendy_print(const char *buf, int len);

/* ── Helpers ────────────────────────────────────────────────────────── */

static int str_len(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void print(const char *msg)
{
    wendy_print(msg, str_len(msg));
}

/* ── GPIO modes (must match wendy_hal.h) ────────────────────────────── */

#define GPIO_MODE_OUTPUT 1
#define GPIO_PULL_NONE   0

/* ── Application entry point ────────────────────────────────────────── */

#define LED_PIN 2   /* Built-in LED on many ESP32 dev boards */

void _start(void)
{
    print("Wendy Blink App starting\n");

    /* Configure LED pin as output */
    if (gpio_configure(LED_PIN, GPIO_MODE_OUTPUT, GPIO_PULL_NONE) != 0) {
        print("ERROR: failed to configure GPIO\n");
        return;
    }

    print("Blinking LED on GPIO 2...\n");

    /* Blink 20 times */
    for (int i = 0; i < 20; i++) {
        gpio_write(LED_PIN, 1);
        timer_delay_ms(500);

        gpio_write(LED_PIN, 0);
        timer_delay_ms(500);
    }

    print("Blink complete.\n");
}
