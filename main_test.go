package main

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestParseSSHTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    sshTarget
		wantErr bool
	}{
		{
			name:  "default port",
			input: "alice@example.com",
			want: sshTarget{
				user:    "alice",
				host:    "example.com",
				port:    "22",
				address: "example.com:22",
			},
		},
		{
			name:  "custom port",
			input: "bob@example.com:2202",
			want: sshTarget{
				user:    "bob",
				host:    "example.com",
				port:    "2202",
				address: "example.com:2202",
			},
		},
		{
			name:    "missing user",
			input:   "example.com:22",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseSSHTarget(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("parseSSHTarget(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestProxyHints(t *testing.T) {
	t.Parallel()

	got := proxyExportBlock("127.0.0.1", 8080)
	want := "" +
		"export http_proxy=http://127.0.0.1:8080\n" +
		"export https_proxy=http://127.0.0.1:8080\n" +
		"export HTTP_PROXY=http://127.0.0.1:8080\n" +
		"export HTTPS_PROXY=http://127.0.0.1:8080\n" +
		"export no_proxy=localhost,127.0.0.1,::1\n" +
		"export NO_PROXY=localhost,127.0.0.1,::1"
	if got != want {
		t.Fatalf("proxyExportBlock mismatch:\n%s", got)
	}

	if proxyUnsetLine() != "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY" {
		t.Fatalf("unexpected unset line: %s", proxyUnsetLine())
	}
}

func TestShutdownHints(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	printShutdownHints(&buf)
	output := buf.String()

	if !strings.Contains(output, "Unset proxy variables on the Ubuntu server:") {
		t.Fatalf("shutdown hints missing header: %s", output)
	}
	if !strings.Contains(output, proxyUnsetLine()) {
		t.Fatalf("shutdown hints missing unset command: %s", output)
	}
}

func TestRootCommandUsesPositionalTarget(t *testing.T) {
	t.Parallel()

	var gotTarget string
	var gotPort int

	cmd := &cobra.Command{
		Use:  "sshhttpbridge user@host[:port]",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gotTarget = args[0]
			port, err := cmd.Flags().GetInt("port")
			if err != nil {
				return err
			}
			gotPort = port
			return nil
		},
	}
	cmd.Flags().Int("port", defaultRemotePort, "")
	cmd.SetArgs([]string{"alice@example.com", "--port", "9090"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if gotTarget != "alice@example.com" {
		t.Fatalf("unexpected target: %s", gotTarget)
	}
	if gotPort != 9090 {
		t.Fatalf("unexpected port: %d", gotPort)
	}
}

func TestRootCommandWithoutArgsPrintsHelp(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd(log.New(io.Discard, "", 0))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "sshhttpbridge user@host[:port]") {
		t.Fatalf("help output missing usage: %s", output)
	}
	if !strings.Contains(output, "Expose a remote HTTP proxy over an SSH reverse tunnel") {
		t.Fatalf("help output missing summary: %s", output)
	}
}
