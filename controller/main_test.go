package main

import (
	"context"
	"strings"
	"testing"
)

func TestParseOptionsDefaults(t *testing.T) {
	got, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	want := options{
		address:          "127.0.0.1:9559",
		deviceID:         1,
		p4InfoPath:       "build/nat.p4info.txtpb",
		deviceConfigPath: "build/nat.json",
	}
	if got != want {
		t.Fatalf("parseOptions() = %+v, want %+v", got, want)
	}
}

func TestParseOptionsExplicitVerifyOnly(t *testing.T) {
	got, err := parseOptions([]string{
		"--address", "127.0.0.1:10559",
		"--device-id", "7",
		"--p4info", "testdata/nat.p4info.txtpb",
		"--device-config", "testdata/nat.json",
		"--verify-only",
	})
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	want := options{
		address:          "127.0.0.1:10559",
		deviceID:         7,
		p4InfoPath:       "testdata/nat.p4info.txtpb",
		deviceConfigPath: "testdata/nat.json",
		verifyOnly:       true,
	}
	if got != want {
		t.Fatalf("parseOptions() = %+v, want %+v", got, want)
	}
}

func TestParseOptionsRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{
			name:    "zero device ID",
			args:    []string{"--device-id", "0"},
			message: "device-id must be non-zero",
		},
		{
			name:    "positional argument",
			args:    []string{"unexpected"},
			message: `unexpected positional argument "unexpected"`,
		},
		{
			name:    "unknown flag",
			args:    []string{"--unknown"},
			message: "flag provided but not defined",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOptions(test.args)
			if err == nil {
				t.Fatal("parseOptions accepted invalid arguments")
			}
			if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("parseOptions error = %q, want it to contain %q", err, test.message)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	if err := run(context.Background(), []string{"--help"}); err != nil {
		t.Fatalf("run --help: %v", err)
	}
}
