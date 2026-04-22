# sshhttpbridge

`sshhttpbridge` is a small Go CLI that opens a reverse SSH tunnel to a target server and exposes an HTTP proxy on the remote side.

The intended use case is:

- your local machine has outbound internet access
- the remote server can be reached over SSH from your machine
- the remote server cannot access the internet directly
- you want the remote server to download packages, binaries, or Go modules through your machine

The program:

- connects to `user@host[:port]` over SSH
- opens a remote listener such as `127.0.0.1:8080`
- handles HTTP and HTTPS proxy traffic inside the same process
- prints `export` commands for the remote shell
- prints the `unset` command again when the bridge shuts down
- reconnects automatically if the SSH session drops

## Features

- Single binary
- No external `ssh` or `tinyproxy` dependency at runtime
- Positional SSH target argument
- HTTP request and CONNECT tunnel logging
- Graceful shutdown on `Ctrl+C`
- SSH key, SSH agent, or password env auth

## Build

```bash
go build -o sshhttpbridge .
```

## Usage

```bash
./sshhttpbridge ubuntu@your.server.ip
./sshhttpbridge ubuntu@your.server.ip --port 3128
./sshhttpbridge ubuntu@your.server.ip --identity ~/.ssh/id_ed25519
```

Show help:

```bash
./sshhttpbridge
./sshhttpbridge --help
```

## Flags

- `--port`
  Remote HTTP proxy port. Default: `8080`
- `--bind`
  Remote bind address on the SSH server. Default: `127.0.0.1`
- `--identity`
  SSH private key path
- `--identity-passphrase-env`
  Environment variable name holding the SSH key passphrase
- `--password-env`
  Environment variable name holding the SSH password
- `--known-hosts`
  Path to `known_hosts`
- `--insecure-host-key`
  Disable host key verification
- `--connect-timeout`
  SSH dial timeout
- `--reconnect-delay`
  Delay before reconnect
- `--keepalive`
  SSH keepalive interval

## Remote Server Workflow

Start the bridge on your local machine:

```bash
./sshhttpbridge ubuntu@your.server.ip --port 8080
```

The program prints commands like:

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export no_proxy=localhost,127.0.0.1,::1
export NO_PROXY=localhost,127.0.0.1,::1
```

Run them on the remote Ubuntu server, then test:

```bash
curl -I https://example.com
```

When the bridge stops, it prints:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
```

## Docker

Build the image:

```bash
docker build -t yourdockerhubuser/sshhttpbridge:latest .
```

Example container run:

```bash
docker run --rm -it \
  -v "$HOME/.ssh:/root/.ssh:ro" \
  -v "$SSH_AUTH_SOCK:/ssh-agent" \
  -e SSH_AUTH_SOCK=/ssh-agent \
  yourdockerhubuser/sshhttpbridge:latest \
  ubuntu@your.server.ip --port 8080
```

If you use private keys from `/root/.ssh`, the container can authenticate without the local `ssh` binary. If you use SSH agent forwarding, mount the agent socket as shown above.

## Publish To Docker Hub

```bash
docker login
docker build -t yourdockerhubuser/sshhttpbridge:latest .
docker push yourdockerhubuser/sshhttpbridge:latest
```

## Suggested Repository Layout

```text
sshhttpbridge-app/
  Dockerfile
  README.md
  go.mod
  go.sum
  main.go
  main_test.go
```

## Notes

- The SSH server must allow TCP forwarding.
- Binding to `127.0.0.1` on the remote side keeps the proxy local to that host.
- This tool is designed around HTTP proxy semantics because many package managers and Go-based tools handle HTTP proxy settings better than SOCKS.

## Repository

Planned repository path:

```text
github.com/horsley/sshHttpBridge
```
