package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"console/liteclient"
)

func run(addr string) error {
	client := liteclient.NewWendyLiteClient(addr)
	if err := client.Connect(); err != nil {
		return err
	}
	defer client.Close()
	fmt.Fprintf(os.Stderr, "connected to %s\n", addr)

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
		case "version":
			major, minor, err := client.GetProtocolVersion()
			if err != nil {
				fmt.Fprintln(os.Stderr, "version:", err)
				continue
			}
			fmt.Printf("protocol version %d.%d\n", major, minor)

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

		case "data":
			arg = strings.TrimSpace(arg)
			if arg == "" {
				fmt.Fprintln(os.Stderr, "usage: data <file>")
				continue
			}
			if err := client.PushApp(arg, nil); err != nil {
				fmt.Fprintln(os.Stderr, "data:", err)
				continue
			}
			fmt.Println("app data pushed")

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

		case "quit", "exit":
			return nil

		default:
			fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
			fmt.Fprintln(os.Stderr, "commands: version, ping, reset, data, start, stop, quit")
		}
	}
	return scanner.Err()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s host:port\n", os.Args[0])
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
