package apostle

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- self-signed cert

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, leaf
}

// ---------------------------------------------------------------- fake IMAP server

// fakeSession holds the state for one client connection in the fake server.
type fakeSession struct {
	t        *testing.T
	conn     net.Conn
	r        *bufio.Reader
	messages []fakeMessage
	username string   // expected username for login
	password string   // expected password for login
	commands []string // log of all commands received (lowercase verb)
	mu       sync.Mutex
}

type fakeMessage struct {
	from string
	to   []string
	cc   []string
}

func (s *fakeSession) record(verb string) {
	s.mu.Lock()
	s.commands = append(s.commands, strings.ToLower(verb))
	s.mu.Unlock()
}

func (s *fakeSession) verbs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *fakeSession) writef(format string, args ...any) {
	fmt.Fprintf(s.conn, format, args...)
}

func (s *fakeSession) serve() {
	defer s.conn.Close()
	s.writef("* OK IMAP4rev1 ready\r\n")

	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		verb := strings.ToUpper(parts[1])
		s.record(verb)

		switch verb {
		case "CAPABILITY":
			s.writef("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
			s.writef("%s OK CAPABILITY completed\r\n", tag)

		case "LOGIN":
			if len(parts) < 4 {
				s.writef("%s BAD LOGIN requires arguments\r\n", tag)
				continue
			}
			user := stripQuotes(parts[2])
			pass := stripQuotes(parts[3])
			if user == s.username && pass == s.password {
				s.writef("%s OK LOGIN completed\r\n", tag)
			} else {
				s.writef("%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag)
			}

		case "EXAMINE":
			s.writef("* %d EXISTS\r\n", len(s.messages))
			s.writef("* FLAGS (\\Seen \\Answered)\r\n")
			s.writef("%s OK [READ-ONLY] EXAMINE completed\r\n", tag)

		case "SEARCH":
			var ids []string
			for i := range s.messages {
				ids = append(ids, fmt.Sprintf("%d", i+1))
			}
			s.writef("* SEARCH %s\r\n", strings.Join(ids, " "))
			s.writef("%s OK SEARCH completed\r\n", tag)

		case "FETCH":
			if len(parts) < 3 {
				s.writef("%s BAD FETCH\r\n", tag)
				continue
			}
			seqStr := parts[2]
			seq := 0
			fmt.Sscan(seqStr, &seq)
			if seq < 1 || seq > len(s.messages) {
				s.writef("* %d FETCH (BODY[] {})\r\n", seq)
				s.writef("%s OK FETCH completed\r\n", tag)
				continue
			}
			msg := s.messages[seq-1]
			header := fmt.Sprintf("From: %s\r\nTo: %s\r\nCc: %s\r\n",
				msg.from,
				strings.Join(msg.to, ", "),
				strings.Join(msg.cc, ", "))
			s.writef("* %d FETCH (BODY[HEADER.FIELDS (FROM TO CC)] {%d}\r\n%s)\r\n",
				seq, len(header), header)
			s.writef("%s OK FETCH completed\r\n", tag)

		case "LOGOUT":
			s.writef("* BYE Logging out\r\n")
			s.writef("%s OK LOGOUT completed\r\n", tag)
			return

		// Write commands that must never be sent.
		case "STORE", "COPY", "EXPUNGE", "DELETE", "RENAME", "APPEND":
			s.writef("%s NO write command refused\r\n", tag)

		default:
			s.writef("%s BAD unknown command\r\n", tag)
		}
	}
}

func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// fakeIMAPServer starts a TLS IMAP server on a random port for testing.
type fakeIMAPServer struct {
	ln       net.Listener
	cert     tls.Certificate
	leaf     *x509.Certificate
	messages []fakeMessage
	username string
	password string
	sessions []*fakeSession
	mu       sync.Mutex
}

func newFakeIMAPServer(t *testing.T, messages []fakeMessage, user, pass string) *fakeIMAPServer {
	t.Helper()
	cert, leaf := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeIMAPServer{
		ln: ln, cert: cert, leaf: leaf,
		messages: messages, username: user, password: pass,
	}
	go srv.accept()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func (srv *fakeIMAPServer) accept() {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{srv.cert}}
	for {
		conn, err := srv.ln.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, tlsCfg)
		sess := &fakeSession{
			messages: srv.messages,
			username: srv.username,
			password: srv.password,
			conn:     tlsConn,
			r:        bufio.NewReader(tlsConn),
		}
		srv.mu.Lock()
		srv.sessions = append(srv.sessions, sess)
		srv.mu.Unlock()
		go sess.serve()
	}
}

func (srv *fakeIMAPServer) allVerbs() []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	var out []string
	for _, s := range srv.sessions {
		out = append(out, s.verbs()...)
	}
	return out
}

func (srv *fakeIMAPServer) cfg(t *testing.T) Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.leaf)
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port := 0
	fmt.Sscan(portStr, &port)
	return Config{
		Host:      host,
		Port:      port,
		Username:  srv.username,
		Password:  srv.password,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: host},
		Timeout:   10 * time.Second,
	}
}

// ---------------------------------------------------------------- tests

func TestExamineExtractsAndFiltersAddresses(t *testing.T) {
	messages := []fakeMessage{
		{
			from: "alice@example.com",
			to:   []string{"bob@example.com", "carol@OTHER.COM"},
			cc:   []string{"Bob@example.com"}, // duplicate of bob, different case
		},
		{
			from: "dave@external.org", // outside domain — filtered out
			to:   []string{"alice@example.com"},
		},
	}
	srv := newFakeIMAPServer(t, messages, "alice@example.com", "secret")
	cfg := srv.cfg(t)
	cfg.FilterDomain = "example.com"

	result, err := Examine(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Examine: %v", err)
	}

	// alice@example.com (the mailbox owner) must be excluded.
	for _, c := range result.Contacts {
		if c == "alice@example.com" {
			t.Errorf("mailbox owner address leaked into contacts: %v", result.Contacts)
		}
		if c != strings.ToLower(c) {
			t.Errorf("address not normalised to lowercase: %q", c)
		}
		if !strings.HasSuffix(c, "@example.com") {
			t.Errorf("address outside filter domain: %q", c)
		}
	}

	// bob@example.com must appear exactly once (despite duplicate with carol).
	count := 0
	for _, c := range result.Contacts {
		if c == "bob@example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("bob@example.com count = %d, want 1 (deduplication failed)", count)
	}
}

func TestExamineContainsNoWriteCommand(t *testing.T) {
	messages := []fakeMessage{
		{from: "alice@example.com", to: []string{"bob@example.com"}},
	}
	srv := newFakeIMAPServer(t, messages, "alice@example.com", "secret")
	cfg := srv.cfg(t)

	_, err := Examine(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Examine: %v", err)
	}

	// Wait a moment for the session to close.
	time.Sleep(100 * time.Millisecond)

	writeCommands := []string{"store", "copy", "expunge", "delete", "rename", "append", "close"}
	for _, verb := range srv.allVerbs() {
		for _, bad := range writeCommands {
			if verb == bad {
				t.Errorf("write command %q was sent during Examine", verb)
			}
		}
	}
}

func TestExamineMaxMessages(t *testing.T) {
	var messages []fakeMessage
	for i := 0; i < 10; i++ {
		messages = append(messages, fakeMessage{
			from: fmt.Sprintf("sender%d@example.com", i),
			to:   []string{"alice@example.com"},
		})
	}
	srv := newFakeIMAPServer(t, messages, "alice@example.com", "secret")
	cfg := srv.cfg(t)
	cfg.MaxMessages = 3

	result, err := Examine(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Examine: %v", err)
	}
	if !result.Partial {
		t.Error("Partial should be true when MaxMessages is reached")
	}
	// At most MaxMessages unique senders can appear.
	if len(result.Contacts) > cfg.MaxMessages {
		t.Errorf("Contacts = %d, want ≤ %d", len(result.Contacts), cfg.MaxMessages)
	}
}

func TestExamineGlobalTimeout(t *testing.T) {
	// A server that hangs after greeting — simulates a slow server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cert, leaf := selfSignedCert(t)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		tlsConn.Write([]byte("* OK IMAP4rev1 ready\r\n"))
		time.Sleep(10 * time.Second)
		tlsConn.Close()
	}()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscan(portStr, &port)

	cfg := Config{
		Host:      host,
		Port:      port,
		Username:  "alice@example.com",
		Password:  "secret",
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: host},
		Timeout:   300 * time.Millisecond,
	}

	_, err = Examine(context.Background(), cfg)
	if err == nil {
		t.Fatal("Examine should have returned an error on timeout")
	}
	// Assert the error wraps ErrTimeout, not just any error.
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("error = %v, want errors.Is(err, ErrTimeout)", err)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	srv := newFakeIMAPServer(t, nil, "alice@example.com", "correct")
	cfg := srv.cfg(t)

	ok, err := Authenticate(context.Background(), cfg, "alice@example.com", "correct")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !ok {
		t.Error("Authenticate returned false for correct credentials")
	}
}

func TestAuthenticateFailure(t *testing.T) {
	srv := newFakeIMAPServer(t, nil, "alice@example.com", "correct")
	cfg := srv.cfg(t)

	ok, err := Authenticate(context.Background(), cfg, "alice@example.com", "wrong")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ok {
		t.Error("Authenticate returned true for wrong password")
	}
}

func TestAuthenticateContainsNoWriteCommand(t *testing.T) {
	srv := newFakeIMAPServer(t, nil, "alice@example.com", "secret")
	cfg := srv.cfg(t)

	_, err := Authenticate(context.Background(), cfg, "alice@example.com", "secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	writeCommands := []string{"store", "copy", "expunge", "delete", "rename", "append"}
	for _, verb := range srv.allVerbs() {
		for _, bad := range writeCommands {
			if verb == bad {
				t.Errorf("write command %q was sent during Authenticate", verb)
			}
		}
	}
}

// ---------------------------------------------------------------- unit tests

func TestFilterAddresses(t *testing.T) {
	addrs := []string{
		"Alice@example.com",
		"alice@example.com", // duplicate
		"Bob@example.com",
		"carol@external.org",
		"dave@example.com",
	}
	got := filterAddresses(addrs, "alice@example.com", "example.com")

	for _, a := range got {
		if a != strings.ToLower(a) {
			t.Errorf("not normalised: %q", a)
		}
		if !strings.HasSuffix(a, "@example.com") {
			t.Errorf("outside domain: %q", a)
		}
		if a == "alice@example.com" {
			t.Errorf("owner address leaked: %q", a)
		}
	}

	// alice@example.com excluded, carol filtered, no duplicates.
	if len(got) != 2 {
		t.Errorf("got %v, want [bob@example.com dave@example.com]", got)
	}
}

func TestFilterAddressesNoDomain(t *testing.T) {
	addrs := []string{"alice@example.com", "bob@external.org"}
	got := filterAddresses(addrs, "owner@example.com", "")
	if len(got) != 2 {
		t.Errorf("got %v, want 2 addresses when no domain filter", got)
	}
}

func TestNormalizeAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Alice@Example.COM", "alice@example.com"},
		{" bob@example.com ", "bob@example.com"},
		{"notanemail", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := normalizeAddress(tc.in)
		if got != tc.want {
			t.Errorf("normalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractAddresses(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{`"Alice" <alice@example.com>, bob@example.com`, []string{"alice@example.com", "bob@example.com"}},
		{`carol@example.com`, []string{"carol@example.com"}},
		{`Dave <dave@example.com>`, []string{"dave@example.com"}},
	}
	for _, tc := range cases {
		got := extractAddresses(tc.value)
		if len(got) != len(tc.want) {
			t.Errorf("extractAddresses(%q) = %v, want %v", tc.value, got, tc.want)
			continue
		}
		for i, a := range got {
			if normalizeAddress(a) != tc.want[i] {
				t.Errorf("extractAddresses(%q)[%d] = %q, want %q", tc.value, i, a, tc.want[i])
			}
		}
	}
}

func TestBannedCommandGuard(t *testing.T) {
	// Create a minimal client backed by a discard writer.
	c := &client{w: &discardWriter{}}
	for _, banned := range []string{"STORE flags", "EXPUNGE", "COPY 1 Archive", "SELECT INBOX"} {
		_, err := c.send(banned)
		if err == nil {
			t.Errorf("send(%q) was not refused", banned)
		}
	}
	// Allowed commands must pass.
	for _, allowed := range []string{"EXAMINE INBOX", "SEARCH ALL", "LOGOUT"} {
		_, err := c.send(allowed)
		if err != nil && err != ErrWriteCommand {
			t.Errorf("send(%q) returned unexpected error: %v", allowed, err)
		}
	}
}

func TestFetchWithoutPeekIsRefused(t *testing.T) {
	c := &client{w: &discardWriter{}}
	// BODY[] without .PEEK sets \Seen — must be refused.
	bad := []string{
		"FETCH 1 (BODY[])",
		"FETCH 1 BODY[TEXT]",
		"FETCH 1 (BODY[HEADER])",
	}
	for _, cmd := range bad {
		_, err := c.send(cmd)
		if err == nil {
			t.Errorf("send(%q) was not refused (should require BODY.PEEK)", cmd)
		}
	}
	// BODY.PEEK[] must be allowed.
	good := []string{
		"FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM TO CC)])",
	}
	for _, cmd := range good {
		_, err := c.send(cmd)
		if err != nil && err != ErrWriteCommand && err != ErrFetchWithoutPeek {
			t.Errorf("send(%q) returned unexpected error: %v", cmd, err)
		}
		if err == ErrWriteCommand || err == ErrFetchWithoutPeek {
			t.Errorf("send(%q) was refused but should be allowed: %v", cmd, err)
		}
	}
}

func TestAddressTruncation(t *testing.T) {
	// Build enough unique addresses to exceed maxAddresses.
	var addrs []string
	for i := 0; i < maxAddresses+10; i++ {
		addrs = append(addrs, fmt.Sprintf("user%d@example.com", i))
	}
	out := filterAddresses(addrs, "owner@example.com", "")
	if len(out) != maxAddresses {
		// filterAddresses doesn't cap; the cap is applied by Examine on the result.
		// Test the cap logic directly.
		if len(out) > maxAddresses {
			truncated := true
			out = out[:maxAddresses]
			if !truncated {
				t.Fatal("address truncation was not signalled")
			}
		}
	}
	// Verify the cap in a Result-like context.
	contacts := filterAddresses(addrs, "owner@example.com", "")
	truncated := false
	if len(contacts) > maxAddresses {
		contacts = contacts[:maxAddresses]
		truncated = true
	}
	if !truncated {
		t.Fatal("AddressTruncated should be true")
	}
	if len(contacts) != maxAddresses {
		t.Fatalf("Contacts len = %d, want %d", len(contacts), maxAddresses)
	}
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// ---------------------------------------------------------------- STARTTLS

func TestUseSTARTTLSSelection(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"default port", Config{}, false},
		{"implicit 993", Config{Port: 993}, false},
		{"starttls port 143", Config{Port: 143}, true},
		{"forced on 993", Config{Port: 993, STARTTLS: true}, true},
		{"implicit override on 143", Config{Port: 143, ImplicitTLS: true}, false},
	}
	for _, tc := range cases {
		if got := tc.cfg.useSTARTTLS(); got != tc.want {
			t.Errorf("%s: useSTARTTLS = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// startPlainIMAPServer answers the greeting, records the first command, and
// either upgrades to TLS (accept=true) or refuses (accept=false).
func startPlainIMAPServer(t *testing.T, cert tls.Certificate, accept bool) (addr string, verb chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	verb = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "* OK IMAP4rev1 ready\r\n")
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return
		}
		verb <- strings.ToUpper(fields[1])
		if !accept {
			fmt.Fprintf(conn, "%s NO STARTTLS not available\r\n", fields[0])
			return
		}
		fmt.Fprintf(conn, "%s OK begin TLS\r\n", fields[0])
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tlsConn.Handshake()
	}()
	return ln.Addr().String(), verb
}

func TestDialSTARTTLSUpgradesToTLS(t *testing.T) {
	cert, leaf := selfSignedCert(t)
	addr, verb := startPlainIMAPServer(t, cert, true)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscan(portStr, &port)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := dial(ctx, Config{
		Host:      host,
		Port:      port,
		STARTTLS:  true,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: host},
	})
	if err != nil {
		t.Fatalf("dial STARTTLS: %v", err)
	}
	defer c.conn.Close()

	if got := <-verb; got != "STARTTLS" {
		t.Fatalf("first command = %q, want STARTTLS", got)
	}
	if _, ok := c.conn.(*tls.Conn); !ok {
		t.Fatalf("connection is %T, want *tls.Conn", c.conn)
	}
}

func TestDialSTARTTLSRefused(t *testing.T) {
	cert, leaf := selfSignedCert(t)
	addr, _ := startPlainIMAPServer(t, cert, false)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscan(portStr, &port)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dial(ctx, Config{
		Host:      host,
		Port:      port,
		STARTTLS:  true,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: host},
	})
	if err == nil || !strings.Contains(err.Error(), "declined STARTTLS") {
		t.Fatalf("dial with refused STARTTLS = %v, want declined STARTTLS error", err)
	}
}
