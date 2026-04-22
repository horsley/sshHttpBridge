package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	defaultRemoteBind = "127.0.0.1"
	defaultRemotePort = 8080
)

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type options struct {
	target                string
	identity              string
	identityPassphraseEnv string
	passwordEnv           string
	knownHosts            string
	insecureHostKey       bool
	remoteBind            string
	remotePort            int
	connectTimeout        time.Duration
	reconnectDelay        time.Duration
	keepAliveInterval     time.Duration
}

type sshTarget struct {
	user    string
	address string
	host    string
	port    string
}

type proxyServer struct {
	logger    *log.Logger
	transport *http.Transport
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := newRootCmd(logger).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd(logger *log.Logger) *cobra.Command {
	opts := defaultOptions()

	cmd := &cobra.Command{
		Use:   "sshhttpbridge user@host[:port]",
		Short: "Expose a remote HTTP proxy over an SSH reverse tunnel",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			opts.target = args[0]
			return run(cmd.Context(), logger, opts)
		},
		SilenceUsage:  false,
		SilenceErrors: true,
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.identity, "identity", opts.identity, "path to SSH private key")
	flags.StringVar(&opts.identityPassphraseEnv, "identity-passphrase-env", "", "environment variable containing the SSH key passphrase")
	flags.StringVar(&opts.passwordEnv, "password-env", "", "environment variable containing the SSH password")
	flags.StringVar(&opts.knownHosts, "known-hosts", opts.knownHosts, "path to known_hosts file")
	flags.BoolVar(&opts.insecureHostKey, "insecure-host-key", false, "skip SSH host key verification")
	flags.StringVar(&opts.remoteBind, "bind", defaultRemoteBind, "remote bind address on the SSH server")
	flags.IntVar(&opts.remotePort, "port", defaultRemotePort, "remote HTTP proxy port on the SSH server")
	flags.DurationVar(&opts.connectTimeout, "connect-timeout", 10*time.Second, "SSH dial timeout")
	flags.DurationVar(&opts.reconnectDelay, "reconnect-delay", 5*time.Second, "delay before reconnect attempts")
	flags.DurationVar(&opts.keepAliveInterval, "keepalive", 30*time.Second, "SSH keepalive interval")

	return cmd
}

func defaultOptions() options {
	return options{
		identity:   firstExisting(expandPath("~/.ssh/id_ed25519"), expandPath("~/.ssh/id_rsa"), expandPath("~/.ssh/id_ecdsa")),
		knownHosts: expandPath("~/.ssh/known_hosts"),
		remoteBind: defaultRemoteBind,
		remotePort: defaultRemotePort,
	}
}

func run(parent context.Context, logger *log.Logger, opts options) error {
	if opts.remotePort < 1 || opts.remotePort > 65535 {
		return fmt.Errorf("invalid --port %d", opts.remotePort)
	}
	opts.identity = expandPath(opts.identity)
	opts.knownHosts = expandPath(opts.knownHosts)

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	authMethods, err := buildAuthMethods(opts)
	if err != nil {
		return fmt.Errorf("build auth methods: %w", err)
	}
	if len(authMethods) == 0 {
		return errors.New("no SSH auth method available; provide --identity, SSH_AUTH_SOCK, or --password-env")
	}

	target, err := parseSSHTarget(opts.target)
	if err != nil {
		return fmt.Errorf("parse target: %w", err)
	}

	hostKeyCallback, err := buildHostKeyCallback(opts)
	if err != nil {
		return fmt.Errorf("build host key callback: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            target.user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         opts.connectTimeout,
	}

	proxy := newProxyServer(logger)
	remoteAddr := net.JoinHostPort(opts.remoteBind, fmt.Sprintf("%d", opts.remotePort))
	logger.Printf("starting bridge to %s via SSH target %s", remoteAddr, target.address)

	var once sync.Once
	for {
		if ctx.Err() != nil {
			logger.Println("shutting down")
			printShutdownHints(os.Stdout)
			return nil
		}

		logger.Printf("dialing SSH %s@%s", target.user, target.address)
		client, err := ssh.Dial("tcp", target.address, clientConfig)
		if err != nil {
			logger.Printf("ssh dial failed: %v", err)
			waitForReconnect(ctx, opts.reconnectDelay)
			continue
		}

		listener, err := client.Listen("tcp", remoteAddr)
		if err != nil {
			_ = client.Close()
			logger.Printf("remote listen failed on %s: %v", remoteAddr, err)
			waitForReconnect(ctx, opts.reconnectDelay)
			continue
		}

		once.Do(func() {
			printUsageHints(os.Stdout, opts.remoteBind, opts.remotePort)
		})
		logger.Printf("remote HTTP proxy ready on %s", remoteAddr)

		keepAliveCtx, keepAliveCancel := context.WithCancel(ctx)
		go keepAliveLoop(keepAliveCtx, client, opts.keepAliveInterval, logger)

		bridgeCtx, bridgeCancel := context.WithCancel(ctx)
		go func() {
			<-bridgeCtx.Done()
			_ = listener.Close()
			_ = client.Close()
		}()

		err = acceptLoop(bridgeCtx, listener, proxy, logger)
		bridgeCancel()
		keepAliveCancel()
		_ = listener.Close()
		_ = client.Close()

		if ctx.Err() != nil {
			logger.Println("shutting down")
			printShutdownHints(os.Stdout)
			return nil
		}

		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("bridge disconnected: %v", err)
		}
		waitForReconnect(ctx, opts.reconnectDelay)
	}
}

func acceptLoop(ctx context.Context, listener net.Listener, proxy *proxyServer, logger *log.Logger) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isClosedConnError(err) {
				return nil
			}
			return err
		}
		go func() {
			if err := proxy.handleConn(conn); err != nil && !errors.Is(err, io.EOF) && !isClosedConnError(err) {
				logger.Printf("proxy connection failed from %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func newProxyServer(logger *log.Logger) *proxyServer {
	return &proxyServer{
		logger: logger,
		transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (p *proxyServer) handleConn(conn net.Conn) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}

	if req.Method == http.MethodConnect {
		return p.handleConnect(conn, reader, req)
	}
	return p.handleHTTP(conn, req)
}

func (p *proxyServer) handleHTTP(conn net.Conn, req *http.Request) error {
	defer req.Body.Close()

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	outReq.Close = true

	if outReq.URL == nil {
		outReq.URL = &url.URL{}
	}
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = outReq.Host
	}
	if outReq.Host == "" {
		outReq.Host = outReq.URL.Host
	}

	start := time.Now()
	target := outReq.URL.String()
	p.logger.Printf("proxy http from=%s method=%s url=%s", conn.RemoteAddr(), outReq.Method, target)

	removeHopHeaders(outReq.Header)
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.logger.Printf("proxy http failed from=%s method=%s url=%s err=%v", conn.RemoteAddr(), outReq.Method, target, err)
		return writeProxyError(conn, http.StatusBadGateway, fmt.Sprintf("upstream request failed: %v", err))
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	resp.Close = true
	resp.Header.Set("Connection", "close")

	p.logger.Printf("proxy http done from=%s method=%s url=%s status=%d duration=%s", conn.RemoteAddr(), outReq.Method, target, resp.StatusCode, time.Since(start).Round(time.Millisecond))
	return resp.Write(conn)
}

func (p *proxyServer) handleConnect(clientConn net.Conn, reader *bufio.Reader, req *http.Request) error {
	defer req.Body.Close()

	start := time.Now()
	p.logger.Printf("proxy connect from=%s target=%s", clientConn.RemoteAddr(), req.Host)

	targetConn, err := net.DialTimeout("tcp", req.Host, 15*time.Second)
	if err != nil {
		p.logger.Printf("proxy connect failed from=%s target=%s err=%v", clientConn.RemoteAddr(), req.Host, err)
		return writeProxyError(clientConn, http.StatusBadGateway, fmt.Sprintf("connect target failed: %v", err))
	}
	defer targetConn.Close()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}

	if buffered := reader.Buffered(); buffered > 0 {
		if _, err := io.CopyN(targetConn, reader, int64(buffered)); err != nil {
			return err
		}
	}

	errCh := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(targetConn, clientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- copyErr
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		copyErr := <-errCh
		if copyErr != nil && !errors.Is(copyErr, net.ErrClosed) && !isClosedConnError(copyErr) && firstErr == nil {
			firstErr = copyErr
		}
	}

	if firstErr != nil {
		p.logger.Printf("proxy connect closed from=%s target=%s duration=%s err=%v", clientConn.RemoteAddr(), req.Host, time.Since(start).Round(time.Millisecond), firstErr)
		return firstErr
	}

	p.logger.Printf("proxy connect closed from=%s target=%s duration=%s", clientConn.RemoteAddr(), req.Host, time.Since(start).Round(time.Millisecond))
	return nil
}

func removeHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}

	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(token); trimmed != "" {
				header.Del(trimmed)
			}
		}
	}
}

func writeProxyError(conn net.Conn, status int, msg string) error {
	resp := &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": {"text/plain; charset=utf-8"},
			"Connection":   {"close"},
		},
		Body:          io.NopCloser(strings.NewReader(msg + "\n")),
		ContentLength: int64(len(msg) + 1),
		Close:         true,
	}
	return resp.Write(conn)
}

func buildAuthMethods(opts options) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if opts.identity != "" {
		signer, err := loadPrivateKeySigner(opts.identity, opts.identityPassphraseEnv)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}

	if opts.passwordEnv != "" {
		password := os.Getenv(opts.passwordEnv)
		if password == "" {
			return nil, fmt.Errorf("environment variable %s is empty", opts.passwordEnv)
		}
		methods = append(methods, ssh.Password(password))
	}

	return methods, nil
}

func loadPrivateKeySigner(path, passphraseEnv string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity %s: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}

	var passErr *ssh.PassphraseMissingError
	if !errors.As(err, &passErr) {
		return nil, fmt.Errorf("parse identity %s: %w", path, err)
	}

	if passphraseEnv == "" {
		return nil, fmt.Errorf("identity %s requires a passphrase; provide --identity-passphrase-env", path)
	}
	passphrase := os.Getenv(passphraseEnv)
	if passphrase == "" {
		return nil, fmt.Errorf("environment variable %s is empty", passphraseEnv)
	}

	signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("parse encrypted identity %s: %w", path, err)
	}
	return signer, nil
}

func buildHostKeyCallback(opts options) (ssh.HostKeyCallback, error) {
	if opts.insecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if _, err := os.Stat(opts.knownHosts); err != nil {
		return nil, fmt.Errorf("known_hosts file %s not found; use --known-hosts or --insecure-host-key", opts.knownHosts)
	}
	return knownhosts.New(opts.knownHosts)
}

func parseSSHTarget(raw string) (sshTarget, error) {
	u, err := url.Parse("ssh://" + raw)
	if err != nil {
		return sshTarget{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return sshTarget{}, fmt.Errorf("missing SSH username in %q", raw)
	}
	host := u.Hostname()
	if host == "" {
		return sshTarget{}, fmt.Errorf("missing SSH host in %q", raw)
	}
	port := u.Port()
	if port == "" {
		port = "22"
	}

	return sshTarget{
		user:    u.User.Username(),
		address: net.JoinHostPort(host, port),
		host:    host,
		port:    port,
	}, nil
}

func waitForReconnect(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func keepAliveLoop(ctx context.Context, client *ssh.Client, interval time.Duration, logger *log.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				logger.Printf("ssh keepalive failed: %v", err)
				_ = client.Close()
				return
			}
		}
	}
}

func printUsageHints(w io.Writer, bind string, port int) {
	addr := net.JoinHostPort(bind, fmt.Sprintf("%d", port))
	fmt.Fprintf(w, "\nRemote proxy is ready on %s\n", addr)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Set these variables on the Ubuntu server:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, proxyExportBlock(bind, port))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The unset command will be printed again when this bridge shuts down.")
	fmt.Fprintln(w)
}

func printShutdownHints(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Unset proxy variables on the Ubuntu server:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, proxyUnsetLine())
	fmt.Fprintln(w)
}

func proxyExportBlock(host string, port int) string {
	proxyURL := fmt.Sprintf("http://%s", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	return strings.Join([]string{
		fmt.Sprintf("export http_proxy=%s", proxyURL),
		fmt.Sprintf("export https_proxy=%s", proxyURL),
		fmt.Sprintf("export HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("export HTTPS_PROXY=%s", proxyURL),
		"export no_proxy=localhost,127.0.0.1,::1",
		"export NO_PROXY=localhost,127.0.0.1,::1",
	}, "\n")
}

func proxyUnsetLine() string {
	return "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY"
}

func expandPath(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

func firstExisting(paths ...string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "closed pipe")
}
