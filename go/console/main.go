package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			if err := client.ResetTargetDevice(); err != nil {
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

		case "quit", "exit":
			return nil

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
			fmt.Fprintln(os.Stderr, "commands: ping, reset, push, start, stop, quit")
		}
	}
	return scanner.Err()
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
