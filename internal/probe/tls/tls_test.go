package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

func TestProbeSuccessfulHandshakeRetainsTLSAndCertificateMetadata(t *testing.T) {
	ca, leaf, cert := testCertificate(t, certificateOptions{DNSNames: []string{"localhost"}})
	server, accepted := startTLSServer(t, &cert, false)
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	result := New(Config{
		Timeout: 2 * time.Second,
		TLSConfig: &cryptotls.Config{
			RootCAs:    roots,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}).Run(context.Background(), probe.ExecutionContext{Target: targetFor(server.Addr().String(), "localhost")})

	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %s, want passed (interpretation=%+v)", result.Status, result.Interpretation)
	}
	if result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("failure reason = %s, want none", result.Interpretation.FailureReason)
	}
	if len(result.Evidence) < 2 {
		t.Fatalf("evidence count = %d, want handshake plus certificate chain", len(result.Evidence))
	}

	var handshake HandshakeEvidence
	decodeEvidence(t, result.Evidence[0], &handshake)
	if handshake.Phase != PhaseComplete || !handshake.HandshakeComplete {
		t.Fatalf("unexpected handshake evidence: %+v", handshake)
	}
	if handshake.TLSVersion == "" || handshake.CipherSuite == "" {
		t.Fatalf("negotiated TLS metadata missing: %+v", handshake)
	}
	if handshake.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", handshake.NegotiatedProtocol)
	}

	var metadata CertificateMetadata
	decodeEvidence(t, result.Evidence[1], &metadata)
	if metadata.ChainIndex != 0 || metadata.Subject == "" || metadata.Issuer == "" {
		t.Fatalf("certificate identity metadata missing: %+v", metadata)
	}
	if metadata.NotBefore == "" || metadata.NotAfter == "" || metadata.SHA256 == "" {
		t.Fatalf("certificate validity/fingerprint metadata missing: %+v", metadata)
	}
	if len(metadata.DNSNames) != 1 || metadata.DNSNames[0] != "localhost" {
		t.Fatalf("certificate SAN metadata = %#v", metadata.DNSNames)
	}
	if strings.Contains(string(result.Evidence[1].Raw), "PRIVATE KEY") {
		t.Fatal("certificate evidence exposed private key material")
	}
	<-accepted
	_ = leaf // retain the leaf in the fixture for the metadata assertions above.
}

func TestProbeDistinguishesTransportFailure(t *testing.T) {
	result := New(Config{
		Timeout: time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fixture transport setup failed")
		},
	}).Run(context.Background(), probe.ExecutionContext{Target: targetFor("127.0.0.1:1", "127.0.0.1")})
	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("status = %s, want failed (interpretation=%+v evidence=%+v)", result.Status, result.Interpretation, result.Evidence)
	}
	if result.Interpretation.FailureReason != FailureReasonTransportFailure {
		t.Fatalf("failure reason = %s, want %s", result.Interpretation.FailureReason, FailureReasonTransportFailure)
	}
	var handshake HandshakeEvidence
	decodeEvidence(t, result.Evidence[0], &handshake)
	if handshake.Phase != PhaseTransport {
		t.Fatalf("phase = %s, want transport", handshake.Phase)
	}
}

func TestProbeNormalizesProtocolHandshakeFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			close(accepted)
			_, _ = conn.Write([]byte("this is not TLS\n"))
			_ = conn.Close()
		}
	}()

	result := NewWithTimeout(time.Second).Run(context.Background(), probe.ExecutionContext{Target: targetFor(listener.Addr().String(), "127.0.0.1")})
	if result.Interpretation.FailureReason != model.FailureReasonTLSHandshakeFailure {
		t.Fatalf("failure reason = %s, want %s", result.Interpretation.FailureReason, model.FailureReasonTLSHandshakeFailure)
	}
	if result.Interpretation.FaultDomain != model.FaultDomainTLS {
		t.Fatalf("fault domain = %s, want tls", result.Interpretation.FaultDomain)
	}
	<-accepted
}

func TestProbeNormalizesCertificateValidationFailures(t *testing.T) {
	ca, _, expiredCert := testCertificate(t, certificateOptions{DNSNames: []string{"localhost"}, Expired: true})
	server, _ := startTLSServer(t, &expiredCert, false)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	expired := New(Config{Timeout: time.Second, TLSConfig: &cryptotls.Config{RootCAs: roots}}).Run(context.Background(), probe.ExecutionContext{Target: targetFor(server.Addr().String(), "localhost")})
	if expired.Interpretation.FailureReason != FailureReasonCertificateExpired {
		t.Fatalf("expired reason = %s, want %s", expired.Interpretation.FailureReason, FailureReasonCertificateExpired)
	}
	if len(expired.Evidence) < 2 {
		t.Fatalf("expired result lost peer certificate metadata: %#v", expired.Evidence)
	}

	_, _, mismatchCert := testCertificate(t, certificateOptions{DNSNames: []string{"different.example"}})
	mismatchServer, _ := startTLSServer(t, &mismatchCert, false)
	defer mismatchServer.Close()
	mismatch := New(Config{Timeout: time.Second, TLSConfig: &cryptotls.Config{RootCAs: roots}}).Run(context.Background(), probe.ExecutionContext{Target: targetFor(mismatchServer.Addr().String(), "localhost")})
	if mismatch.Interpretation.FailureReason != FailureReasonCertificateHostnameMismatch {
		t.Fatalf("hostname reason = %s, want %s", mismatch.Interpretation.FailureReason, FailureReasonCertificateHostnameMismatch)
	}

	_, _, untrustedCert := testCertificate(t, certificateOptions{DNSNames: []string{"localhost"}})
	untrustedServer, _ := startTLSServer(t, &untrustedCert, false)
	defer untrustedServer.Close()
	untrusted := NewWithTimeout(time.Second).Run(context.Background(), probe.ExecutionContext{Target: targetFor(untrustedServer.Addr().String(), "localhost")})
	if untrusted.Interpretation.FailureReason != FailureReasonUnknownAuthority {
		t.Fatalf("authority reason = %s, want %s", untrusted.Interpretation.FailureReason, FailureReasonUnknownAuthority)
	}
}

func TestProbeNormalizesTLSTimeoutAndCancellation(t *testing.T) {
	server, accepted := startTLSServer(t, nil, true)
	defer server.Close()

	timeoutResult := NewWithTimeout(35*time.Millisecond).Run(context.Background(), probe.ExecutionContext{Target: targetFor(server.Addr().String(), "127.0.0.1")})
	if timeoutResult.Interpretation.FailureReason != FailureReasonTLSTimeout {
		t.Fatalf("timeout reason = %s, want %s", timeoutResult.Interpretation.FailureReason, FailureReasonTLSTimeout)
	}
	<-accepted

	cancelServer, cancelAccepted := startTLSServer(t, nil, true)
	defer cancelServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-cancelAccepted
		cancel()
	}()
	canceled := NewWithTimeout(time.Second).Run(ctx, probe.ExecutionContext{Target: targetFor(cancelServer.Addr().String(), "127.0.0.1")})
	if canceled.Interpretation.FailureReason != FailureReasonCancellation {
		t.Fatalf("cancellation reason = %s, want %s", canceled.Interpretation.FailureReason, FailureReasonCancellation)
	}
}

type certificateOptions struct {
	DNSNames []string
	Expired  bool
}

func testCertificate(t *testing.T, options certificateOptions) (*x509.Certificate, *x509.Certificate, cryptotls.Certificate) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tadori Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafNotBefore, leafNotAfter := now.Add(-time.Hour), now.Add(24*time.Hour)
	if options.Expired {
		leafNotBefore, leafNotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Tadori Test Server"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		DNSNames:     options.DNSNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := cryptotls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKey.Certificate = [][]byte{leafDER, caDER}
	return ca, leaf, privateKey
}

func startTLSServer(t *testing.T, certificate *cryptotls.Certificate, hold bool) (net.Listener, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		if hold {
			// The client timeout/cancellation closes this connection.
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
			return
		}
		server := cryptotls.Server(conn, &cryptotls.Config{Certificates: []cryptotls.Certificate{*certificate}, NextProtos: []string{"h2"}})
		_ = server.Handshake()
		_ = server.Close()
	}()
	return listener, accepted
}

func targetFor(address, host string) model.Target {
	_, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	return model.Target{Scheme: "https", Host: host, Port: uint16(port)}
}

func decodeEvidence(t *testing.T, evidence model.Evidence, target any) {
	t.Helper()
	if err := json.Unmarshal(evidence.Raw, target); err != nil {
		t.Fatalf("decode evidence %s: %v", evidence.ID, err)
	}
}
