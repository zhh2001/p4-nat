package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
)

const operationTimeout = 20 * time.Second

type options struct {
	address          string
	deviceID         uint64
	p4InfoPath       string
	deviceConfigPath string
	verifyOnly       bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}

	p4InfoText, err := os.ReadFile(opts.p4InfoPath)
	if err != nil {
		return fmt.Errorf("read P4Info: %w", err)
	}
	deviceConfig, err := os.ReadFile(opts.deviceConfigPath)
	if err != nil {
		return fmt.Errorf("read device config: %w", err)
	}
	pl, err := pipeline.LoadText(p4InfoText, deviceConfig)
	if err != nil {
		return fmt.Errorf("load pipeline: %w", err)
	}

	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()

	c, err := client.Dial(ctx, opts.address,
		client.WithDeviceID(opts.deviceID),
		client.WithElectionID(client.ElectionID{Low: 1}),
		client.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("connect to switch: %w", err)
	}
	defer c.Close()

	if !opts.verifyOnly {
		if err := c.BecomePrimary(ctx); err != nil {
			return fmt.Errorf("become primary: %w", err)
		}
		if _, err := c.SetPipeline(ctx, pl, client.SetPipelineOptions{}); err != nil {
			return fmt.Errorf("install pipeline: %w", err)
		}
	}
	installed, err := c.GetPipeline(ctx)
	if err != nil {
		return fmt.Errorf("read pipeline: %w", err)
	}
	if !proto.Equal(pl.Info(), installed.Info()) ||
		!bytes.Equal(pl.DeviceConfig(), installed.DeviceConfig()) {
		return errors.New("installed pipeline does not match requested pipeline")
	}

	entries, err := configurationEntries(pl)
	if err != nil {
		return err
	}
	if !opts.verifyOnly {
		updates := makeUpdates(entries)
		if err := c.Write(ctx, client.WriteOptions{}, updates...); err != nil {
			return fmt.Errorf("program table entries: %w", err)
		}
	}
	readback, err := c.ReadTableEntries(ctx, 0)
	if err != nil {
		return fmt.Errorf("read table entries: %w", err)
	}
	if err := verifyEntries(entries, readback); err != nil {
		return fmt.Errorf("verify table entries: %w", err)
	}

	if opts.verifyOnly {
		fmt.Printf("verified %d table entries\n", len(entries))
	} else {
		fmt.Printf("configured and verified %d table entries\n", len(entries))
	}
	return nil
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("p4natctl", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&opts.address, "address", "127.0.0.1:9559", "P4Runtime server address")
	flags.Uint64Var(&opts.deviceID, "device-id", 1, "P4Runtime device ID")
	flags.StringVar(&opts.p4InfoPath, "p4info", "build/nat.p4info.txtpb", "P4Info text file")
	flags.StringVar(&opts.deviceConfigPath, "device-config", "build/nat.json", "BMv2 JSON file")
	flags.BoolVar(&opts.verifyOnly, "verify-only", false, "verify the installed configuration without changing it")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	if opts.deviceID == 0 {
		return options{}, errors.New("device-id must be non-zero")
	}
	return opts, nil
}
