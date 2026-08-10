package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/wendylabsinc/wendy/go/console/liteclient"
)

func run(target string) error {
	client := liteclient.NewWendyLiteClient()
	var err error
	switch {
	case strings.HasPrefix(target, "/"):
		err = client.ConnectToSerial(target)
	case strings.HasPrefix(target, "cloud://"):
		var addr string
		var assetID uint32
		addr, assetID, err = parseCloudTarget(target)
		if err == nil {
			err = client.ConnectViaCloudInsecure(addr, assetID)
		}
	default:
		err = client.ConnectInsecure(target)
	}
	if err != nil {
		return err
	}
	defer client.Close()
	fmt.Fprintf(os.Stderr, "connected to %s\n", target)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")

		switch cmd {
		case "ping":
			if err := client.Ping(); err != nil {
				fmt.Fprintln(os.Stderr, "ping:", err)
				continue
			}
			fmt.Println("pong")

		case "reset":
			autoStart, delay, ok := true, time.Duration(0), true
			for _, flag := range strings.Fields(arg) {
				switch {
				case flag == "--noautostart":
					autoStart = false
				case strings.HasPrefix(flag, "--delay="):
					ms, err := strconv.ParseUint(strings.TrimPrefix(flag, "--delay="), 10, 32)
					if err != nil {
						ok = false
					}
					delay = time.Duration(ms) * time.Millisecond
				default:
					ok = false
				}
			}
			if !ok {
				fmt.Fprintln(os.Stderr, "usage: reset [--noautostart] [--delay=<ms>]")
				continue
			}
			if err := client.ResetTargetDevice(autoStart, delay); err != nil {
				fmt.Fprintln(os.Stderr, "reset:", err)
				continue
			}
			fmt.Println("resetting…")

		case "push":
			arg = strings.TrimSpace(arg)
			if arg == "" {
				fmt.Fprintln(os.Stderr, "usage: push <file.bin|file.wasm>")
				continue
			}
			var appType liteclient.AppType
			var appKind string
			switch strings.ToLower(filepath.Ext(arg)) {
			case ".bin":
				appType = liteclient.AppTypeNative
				appKind = "native"
			case ".wasm":
				appType = liteclient.AppTypeWasm
				appKind = "wasm"
			default:
				fmt.Fprintf(os.Stderr, "push: unsupported file extension %q (want .bin or .wasm)\n", filepath.Ext(arg))
				continue
			}
			if err := client.PushApp(arg, appType, nil); err != nil {
				fmt.Fprintln(os.Stderr, "push:", err)
				continue
			}
			fmt.Printf("%s app pushed\n", appKind)

		case "start":
			if err := client.StartApp(); err != nil {
				fmt.Fprintln(os.Stderr, "start:", err)
				continue
			}
			fmt.Println("app started")

		case "stop":
			if err := client.StopApp(); err != nil {
				fmt.Fprintln(os.Stderr, "stop:", err)
				continue
			}
			fmt.Println("app stopped")

		case "identity":
			identity, err := client.GetDeviceIdentity(0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "identity:", err)
				continue
			}
			fmt.Printf("id:           %s\n", identity.ID)
			fmt.Printf("name:         %s\n", identity.Name)
			fmt.Printf("display_name: %s\n", identity.DisplayName)

		case "info":
			info, err := client.GetDeviceInfo(0)
			if err != nil {
				fmt.Fprintln(os.Stderr, "info:", err)
				continue
			}
			fmt.Printf("os:                 %s\n", info.OS)
			fmt.Printf("os_version:         %s\n", info.OSVersion)
			fmt.Printf("cpu_architecture:   %s\n", info.CPUArchitecture)
			fmt.Printf("board:              %s\n", info.Board)
			fmt.Printf("wasm_app_support:   %t\n", info.WasmAppSupport)
			fmt.Printf("native_app_support: %t\n", info.NativeAppSupport)

		case "console":
			rolling, blocking, ok := false, true, true
			for _, flag := range strings.Fields(arg) {
				switch flag {
				case "--rolling":
					rolling = true
				case "--noblocking":
					blocking = false
				default:
					ok = false
				}
			}
			if !ok {
				fmt.Fprintln(os.Stderr, "usage: console [--rolling] [--noblocking]")
				continue
			}
			runConsole(client, rolling, blocking)

		case "quit", "exit":
			return nil

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
			fmt.Fprintln(os.Stderr, "commands: ping, reset, push, start, stop, identity, info, console, quit")
		}
	}
	return scanner.Err()
}

// runConsole streams the device's console output and forwards keystrokes to
// the device's stdin, with the local terminal in raw mode, until the user
// presses Ctrl-C. It never returns before the stdin-reader goroutine has
// stopped: the REPL reads os.Stdin next, and two concurrent readers would
// steal each other's bytes.
func runConsole(client *liteclient.WendyLiteClient, rolling bool, blocking bool) {
	const ctrlC = 0x03

	ch, detach, err := client.ConsoleAttach(rolling, blocking)
	if err != nil {
		fmt.Fprintln(os.Stderr, "console attach:", err)
		return
	}
	fmt.Fprintln(os.Stderr, "console attached — press Ctrl-C to stop")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw mode:", err)
		if err := detach(true); err != nil {
			fmt.Fprintln(os.Stderr, "console detach:", err)
		}
		return
	}
	restore := func() { term.Restore(int(os.Stdin.Fd()), oldState) }

	quit := make(chan struct{})
	go func() {
		defer close(quit)
		buf := make([]byte, 1024)
		forward := true
		for {
			n, err := os.Stdin.Read(buf)
			data := buf[:n]
			last := false
			if i := bytes.IndexByte(data, ctrlC); i >= 0 {
				data, last = data[:i], true
			}
			if len(data) > 0 && forward {
				// A dead link fails every send; stop forwarding but keep
				// reading so the terminal is handed back only on Ctrl-C.
				forward = client.ConsolePushStdinData(data) == nil
			}
			if last || err != nil {
				return
			}
		}
	}()

	for {
		select {
		case chunk, ok := <-ch:
			if !ok {
				fmt.Fprint(os.Stderr, "connection lost — press Ctrl-C\r\n")
				<-quit
				restore()
				return
			}
			w := os.Stdout
			if chunk.Stderr {
				w = os.Stderr
			}
			if chunk.Gap {
				fmt.Fprint(w, "[…output lost…]")
			}
			// Raw mode disables output post-processing, so bare LFs from the
			// device would stair-step without this.
			w.Write(bytes.ReplaceAll(chunk.Data, []byte("\n"), []byte("\r\n")))
		case <-quit:
			restore()
			if err := detach(false); err != nil {
				fmt.Fprintln(os.Stderr, "console detach:", err)
			}
			return
		}
	}
}

// parseCloudTarget splits cloud://host:port[/asset-id] into the tinycloud
// gRPC address and the target asset id (default 23).
func parseCloudTarget(target string) (string, uint32, error) {
	rest := strings.TrimPrefix(target, "cloud://")
	addr, assetPart, hasAsset := strings.Cut(rest, "/")
	if addr == "" {
		return "", 0, fmt.Errorf("usage: cloud://host:port[/asset-id]")
	}
	assetID := uint64(23)
	if hasAsset && assetPart != "" {
		var err error
		assetID, err = strconv.ParseUint(assetPart, 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("bad asset id %q: %w", assetPart, err)
		}
	}
	return addr, uint32(assetID), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s host:port|/dev/ttyXXX|cloud://host:port[/asset-id]\n", os.Args[0])
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
