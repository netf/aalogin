package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"aalogin/internal/cli"
	"aalogin/internal/login"
)

var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	opts, err := cli.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if opts.Help {
		cli.Help(os.Stdout)
		return 0
	}
	if opts.Version {
		fmt.Fprintln(os.Stdout, version)
		return 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan struct{})
	signalCode := make(chan int, 1)
	go func() {
		select {
		case s := <-signals:
			code := 130
			if s == syscall.SIGTERM {
				code = 143
			}
			signalCode <- code
			cancel()
		case <-done:
		}
	}()
	runner := login.New(os.Stdin, os.Stdout, os.Stderr)
	err = runner.Run(ctx, opts)
	close(done)
	select {
	case code := <-signalCode:
		return code
	default:
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if login.IsConfigError(err) {
			return 2
		}
		return 1
	}
	return 0
}
