package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"console/liteclient"
)

func run(target string) error {
	client := liteclient.NewWendyLiteClient()
	var err error
	if strings.HasPrefix(target, "/") {
		err = client.ConnectToSerial(target)
	} else {
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
			runConsole(client, scanner, rolling, blocking)

		case "quit", "exit":
			return nil

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
			fmt.Fprintln(os.Stderr, "commands: ping, reset, push, start, stop, identity, info, console, quit")
		}
	}
	return scanner.Err()
}

// runConsole streams the device's console output until the user presses
// Enter. It never returns before the Enter-watcher goroutine's Scan has
// completed: the REPL reuses scanner, and two concurrent Scan calls on one
// bufio.Scanner are invalid.
func runConsole(client *liteclient.WendyLiteClient, scanner *bufio.Scanner, rolling bool, blocking bool) {
	ch, detach, err := client.ConsoleAttach(rolling, blocking)
	if err != nil {
		fmt.Fprintln(os.Stderr, "console attach:", err)
		return
	}
	fmt.Fprintln(os.Stderr, "streaming console output — press Enter to stop")

	enter := make(chan struct{})
	go func() {
		scanner.Scan()
		close(enter)
	}()

	for {
		select {
		case chunk, ok := <-ch:
			if !ok {
				fmt.Fprintln(os.Stderr, "connection lost — press Enter")
				<-enter
				return
			}
			w := os.Stdout
			if chunk.Stderr {
				w = os.Stderr
			}
			if chunk.Gap {
				fmt.Fprint(w, "[…output lost…]")
			}
			w.Write(chunk.Data)
		case <-enter:
			if err := detach(); err != nil {
				fmt.Fprintln(os.Stderr, "console detach:", err)
			}
			return
		}
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s host:port|/dev/ttyXXX\n", os.Args[0])
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
