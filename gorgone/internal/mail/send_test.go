package mail

import (
	"bufio"
	"bytes"
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
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	"github.com/siren-core/gorgone/internal/store"
)

// ---------------------------------------------------------------- SMTP unit tests

func TestEnvelopeAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "alice@example.com"},
		{"Alice <alice@example.com>", "alice@example.com"},
		{"=?utf-8?q?Siren_Platform?= <siren@example.com>", "siren@example.com"},
		{" bob@example.com ", "bob@example.com"},
	}
	for _, tc := range cases {
		got := envelopeAddress(tc.in)
		if got != tc.want {
			t.Errorf("envelopeAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewSenderRejectsEmptyHost(t *testing.T) {
	if _, err := NewSender(SMTPConfig{}); err == nil {
		t.Fatal("empty host accepted")
	}
}

// selfSignedCert generates an in-memory TLS certificate for 127.0.0.1.
func selfSignedCert(t *testing.T) tls.Certificate {
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
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})
	cert, err := tls.X509KeyPair(certPEM, keyPEMBlock)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeSMTPServer is a minimal SMTP server used by tests. It speaks EHLO,
// offers STARTTLS, upgrades the connection and collects the DATA payload.
type fakeSMTPServer struct {
	tlsCfg   *tls.Config
	received chan []byte // receives the raw DATA body
}

func newFakeSMTPServer(t *testing.T) (*fakeSMTPServer, net.Listener, *x509.Certificate) {
	t.Helper()
	cert := selfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	// Parse the leaf certificate so the client can pin it.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeSMTPServer{
		tlsCfg:   tlsCfg,
		received: make(chan []byte, 1),
	}
	go srv.accept(ln)
	return srv, ln, leaf
}

func (s *fakeSMTPServer) accept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	tp := textproto.NewConn(conn)
	tp.PrintfLine("220 test.local ESMTP")

	line, err := tp.ReadLine()
	if err != nil || !strings.HasPrefix(line, "EHLO") {
		return
	}
	tp.PrintfLine("250-test.local")
	tp.PrintfLine("250 STARTTLS")

	line, err = tp.ReadLine()
	if err != nil || line != "STARTTLS" {
		return
	}
	tp.PrintfLine("220 Ready to start TLS")

	// Upgrade to TLS.
	tlsConn := tls.Server(conn, s.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	tp = textproto.NewConn(tlsConn)
	// Post-TLS EHLO.
	line, _ = tp.ReadLine()
	if !strings.HasPrefix(line, "EHLO") {
		return
	}
	tp.PrintfLine("250-test.local")
	tp.PrintfLine("250 OK")

	// MAIL FROM
	_, _ = tp.ReadLine()
	tp.PrintfLine("250 OK")

	// RCPT TO
	_, _ = tp.ReadLine()
	tp.PrintfLine("250 OK")

	// DATA
	_, _ = tp.ReadLine()
	tp.PrintfLine("354 Start mail input")

	var body bytes.Buffer
	r := bufio.NewReader(tlsConn)
	for {
		l, err := r.ReadString('\n')
		body.WriteString(l)
		if err != nil || strings.HasSuffix(strings.TrimRight(l, "\r\n"), ".") {
			break
		}
		if strings.TrimSpace(l) == "." {
			break
		}
	}
	tp.PrintfLine("250 Message accepted")

	_, _ = tp.ReadLine() // QUIT
	tp.PrintfLine("221 Bye")

	select {
	case s.received <- body.Bytes():
	default:
	}
}

// TestSenderSTARTTLSNominalPath verifies the full happy path: EHLO →
// STARTTLS → TLS upgrade → MAIL FROM → RCPT TO → DATA → QUIT. It asserts that
// the server received the message bytes and that they contain the subject line.
func TestSenderSTARTTLSNominalPath(t *testing.T) {
	srv, ln, leaf := newFakeSMTPServer(t)
	defer ln.Close()

	// Build a certificate pool that trusts the self-signed cert.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscan(portStr, &port)

	sender, err := NewSender(SMTPConfig{
		Host: host,
		Port: port,
		// Override TLS config for the test so we pin the self-signed cert.
		tlsConfig: &tls.Config{
			ServerName: host,
			RootCAs:    pool,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		From: "siren@example.com", To: "alice@example.com",
		Subject: "gate test", MessageID: "abc@siren",
		Date: time.Now(), HTMLBody: []byte("<p>hello</p>"), TextBody: []byte("hello"),
		SelectedLang: "fr",
	}
	if err := sender.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case body := <-srv.received:
		if !bytes.Contains(body, []byte("gate")) {
			t.Errorf("server did not receive the subject:\n%s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive a message")
	}
}

// TestSenderDialsAndTransacts verifies the SMTP sequence when STARTTLS is
// declined (454). The sender must propagate the error.
func TestSenderDialsAndTransacts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		tp := textproto.NewConn(conn)
		tp.PrintfLine("220 test.local ESMTP")
		cmd, _ := tp.ReadLine()
		if !strings.HasPrefix(cmd, "EHLO") {
			done <- "want EHLO, got: " + cmd
			return
		}
		tp.PrintfLine("250-test.local")
		tp.PrintfLine("250 STARTTLS")

		cmd, _ = tp.ReadLine()
		if cmd != "STARTTLS" {
			done <- "want STARTTLS, got: " + cmd
			return
		}
		tp.PrintfLine("454 TLS not available")
		done <- "ok"
		_ = bufio.NewReader(conn) // drain
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscan(portStr, &port)

	sender, err := NewSender(SMTPConfig{Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		From: "siren@example.com", To: "alice@example.com",
		Subject: "test", MessageID: "abc@siren",
		Date: time.Now(), HTMLBody: []byte("<p>hi</p>"), TextBody: []byte("hi"),
	}
	err = sender.Send(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error from declined STARTTLS, got nil")
	}
	if !strings.Contains(err.Error(), "starttls") && !strings.Contains(err.Error(), "454") {
		t.Errorf("error = %v, want STARTTLS or 454", err)
	}

	result := <-done
	if result != "ok" {
		t.Fatalf("fake server: %s", result)
	}
}

// ---------------------------------------------------------------- Send / Runner tests

type memOps struct {
	contacts []store.Contact
	sends    []*store.Send
	failAt   map[string]struct{} // contact IDs whose RecordSend should fail
}

func newMemOps(contacts ...store.Contact) *memOps {
	return &memOps{contacts: contacts, failAt: make(map[string]struct{})}
}

func (m *memOps) ListContacts(_ context.Context, _ string) ([]store.Contact, error) {
	return append([]store.Contact(nil), m.contacts...), nil
}

func (m *memOps) ListSendsByCampaign(_ context.Context, _ string) ([]store.Send, error) {
	out := make([]store.Send, len(m.sends))
	for i, s := range m.sends {
		out[i] = *s
	}
	return out, nil
}

func (m *memOps) RecordSend(_ context.Context, in store.SendInput) (*store.Send, error) {
	if _, fail := m.failAt[in.ContactID]; fail {
		return nil, errors.New("store: injected failure")
	}
	s := &store.Send{
		ID:         in.ContactID + "-send",
		ContactID:  in.ContactID,
		TemplateID: in.TemplateID,
		StepID:     in.StepID,
		Status:     in.Status,
		SentAt:     in.SentAt,
	}
	m.sends = append(m.sends, s)
	return s, nil
}

type failSender struct{ err error }

func (f *failSender) Send(_ context.Context, _ *Message) error { return f.err }

func testRunner(t *testing.T, ops Ops, sender interface {
	Send(context.Context, *Message) error
}, dryRun bool, priorStep ...string) *Runner {
	t.Helper()
	prior := ""
	if len(priorStep) > 0 {
		prior = priorStep[0]
	}
	r, err := NewRunner(RunnerConfig{
		Composer:  testComposer(t),
		Sender:    sender,
		Ops:       ops,
		Resolve:   func(campaignID, templateID, stepID string) (collect.Step, error) { return testStep(), nil },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		DryRun:    dryRun,
		PriorStep: prior,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func makeContact(id, email, lang string) store.Contact {
	vars := map[string]string{"email": email}
	if lang != "" {
		vars["lang"] = lang
	}
	return store.Contact{
		ID:    id,
		Email: email,
		Vars:  vars,
	}
}

func TestSendSuccessAndCountsContacts(t *testing.T) {
	ops := newMemOps(
		makeContact("alice", "alice@example.com", "fr"),
		makeContact("bob", "bob@example.com", "en"),
	)
	sender := senderFunc(func(_ context.Context, _ *Message) error { return nil })
	r := testRunner(t, ops, sender, false)

	sum, err := r.Send(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sum.Sent != 2 || sum.Failed != 0 || sum.Skipped != 0 {
		t.Fatalf("summary = %s", sum)
	}
	if len(ops.sends) != 2 {
		t.Fatalf("recorded sends = %d, want 2", len(ops.sends))
	}
	for _, s := range ops.sends {
		if s.Status != StatusSent {
			t.Errorf("send %s status = %q, want %q", s.ContactID, s.Status, StatusSent)
		}
	}
}

func TestSendSmtpFailureContinuesAndRecordsFailed(t *testing.T) {
	ops := newMemOps(
		makeContact("alice", "alice@example.com", "fr"),
		makeContact("bob", "bob@example.com", "en"),
		makeContact("carol", "carol@example.com", "de"),
	)
	failSend := senderFunc(func(_ context.Context, msg *Message) error {
		if strings.HasPrefix(msg.To, "bob") {
			return errors.New("SMTP 550 mailbox full")
		}
		return nil
	})
	r := testRunner(t, ops, failSend, false)

	sum, err := r.Send(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sum.Sent != 2 || sum.Failed != 1 || sum.Skipped != 0 {
		t.Fatalf("summary = %s", sum)
	}

	var sentCount, failCount int
	for _, s := range ops.sends {
		if s.Status == StatusSent {
			sentCount++
		} else if strings.HasPrefix(s.Status, statusFailed) {
			failCount++
		}
	}
	if sentCount != 2 || failCount != 1 {
		t.Fatalf("recorded sent=%d failed=%d, want 2/1", sentCount, failCount)
	}
}

func TestSendIdempotentSkipsAlreadySent(t *testing.T) {
	contacts := []store.Contact{
		makeContact("alice", "alice@example.com", "fr"),
		makeContact("bob", "bob@example.com", "en"),
	}
	ops := newMemOps(contacts...)
	ops.sends = append(ops.sends, &store.Send{
		ID: "pre", ContactID: "alice",
		TemplateID: "tmp-001", StepID: "a",
		Status: StatusSent, SentAt: time.Now(),
	})

	var deliveredTo []string
	captureSender := senderFunc(func(_ context.Context, msg *Message) error {
		deliveredTo = append(deliveredTo, msg.To)
		return nil
	})
	r := testRunner(t, ops, captureSender, false)

	sum, err := r.Send(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sum.Sent != 1 || sum.Skipped != 1 {
		t.Fatalf("summary = %s", sum)
	}
	if len(deliveredTo) != 1 || !strings.Contains(deliveredTo[0], "bob") {
		t.Fatalf("delivered to %v, want only bob", deliveredTo)
	}
}

func TestSendDryRunSendsNothingAndWritesNothing(t *testing.T) {
	ops := newMemOps(
		makeContact("alice", "alice@example.com", "fr"),
		makeContact("bob", "bob@example.com", "en"),
	)
	r := testRunner(t, ops, nil, true)
	r.sender = nil // confirm nil is safe

	sum, err := r.Send(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Send dry-run: %v", err)
	}
	if sum.Sent != 2 {
		t.Fatalf("dry-run sent count = %d, want 2", sum.Sent)
	}
	if len(ops.sends) != 0 {
		t.Fatalf("dry-run wrote %d sends, want 0", len(ops.sends))
	}
}

func TestNewRunnerRequiresSenderWhenNotDryRun(t *testing.T) {
	ops := newMemOps()
	_, err := NewRunner(RunnerConfig{
		Composer: testComposer(t),
		Sender:   nil,
		Ops:      ops,
		Resolve:  func(_, _, _ string) (collect.Step, error) { return testStep(), nil },
	})
	if err == nil {
		t.Fatal("nil sender accepted when not dry-run")
	}
}

func TestSendVariantByContactLang(t *testing.T) {
	ops := newMemOps(
		makeContact("alice", "alice@example.com", "fr"),
		makeContact("bob", "bob@example.com", "de"),
	)
	var selectedLangs []string
	captureSender := senderFunc(func(_ context.Context, msg *Message) error {
		selectedLangs = append(selectedLangs, msg.SelectedLang)
		return nil
	})
	r := testRunner(t, ops, captureSender, false)

	if _, err := r.Send(context.Background(), "acme"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for _, lang := range selectedLangs {
		if lang == "" {
			t.Error("SelectedLang is empty; variant was not selected")
		}
	}
}

func TestSendPriorStepGatesDelivery(t *testing.T) {
	ops := newMemOps(
		makeContact("alice", "alice@example.com", "fr"), // has prior step "a"
		makeContact("bob", "bob@example.com", "en"),     // no prior step "a"
	)
	// Alice has a successful send for step "a".
	ops.sends = append(ops.sends, &store.Send{
		ID: "pre-alice", ContactID: "alice",
		TemplateID: "tmp-001", StepID: "a",
		Status: StatusSent, SentAt: time.Now(),
	})

	var deliveredTo []string
	captureSender := senderFunc(func(_ context.Context, msg *Message) error {
		deliveredTo = append(deliveredTo, msg.To)
		return nil
	})

	// Use a runner for step "b" (identifier step) gated on prior step "a".
	// The composer still uses step "a" for rendering (re-uses testComposer),
	// but the Runner is configured with a different logical step label to prove
	// PriorStep filtering is independent of what is composed.
	comp, err := NewComposer(Config{
		Renderer:    testRenderer(t),
		FromAddress: "siren@example.com",
		BaseURL:     "https://siren.example.com",
		Campaign:    "acme",
		Template:    "tmp-001",
		Step:        "b", // step B — alice received step A, bob did not
	})
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewRunner(RunnerConfig{
		Composer:  comp,
		Sender:    captureSender,
		Ops:       ops,
		Resolve:   func(_, _, _ string) (collect.Step, error) { return testStep(), nil },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		PriorStep: "a",
	})
	if err != nil {
		t.Fatal(err)
	}

	sum, err := r.Send(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sum.Sent != 1 || sum.Skipped != 1 {
		t.Fatalf("summary = %s, want sent=1 skipped=1", sum)
	}
	if len(deliveredTo) != 1 || !strings.Contains(deliveredTo[0], "alice") {
		t.Fatalf("delivered to %v, want only alice", deliveredTo)
	}
}

// senderFunc adapts a function to the Sender interface.
type senderFunc func(context.Context, *Message) error

func (f senderFunc) Send(ctx context.Context, msg *Message) error { return f(ctx, msg) }
