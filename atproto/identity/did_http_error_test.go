package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

func TestResolveDIDPreservesHTTPStatus(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			dir := &BaseDirectory{PLCURL: server.URL, HTTPClient: *server.Client()}
			_, err := dir.ResolveDID(context.Background(), syntax.DID("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"))
			if !errors.Is(err, ErrDIDResolutionFailed) {
				t.Fatalf("expected resolution failure, got %v", err)
			}
			var response *DIDHTTPError
			if !errors.As(err, &response) || response.StatusCode != status {
				t.Fatalf("expected HTTP %d, got %v", status, err)
			}
		})
	}
}

func TestResolveDIDDistinguishesMalformedDocuments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer server.Close()
	dir := &BaseDirectory{PLCURL: server.URL, HTTPClient: *server.Client()}
	_, err := dir.ResolveDID(context.Background(), syntax.DID("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"))
	if !errors.Is(err, ErrDIDResolutionFailed) {
		t.Fatalf("expected resolution failure, got %v", err)
	}
	var response *DIDHTTPError
	if errors.As(err, &response) {
		t.Fatalf("malformed identity document must not look like an HTTP outage: %v", err)
	}
}

func TestResolveDIDWebPreservesHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	dir := &BaseDirectory{HTTPClient: http.Client{Transport: transport}}
	_, err := dir.ResolveDID(context.Background(), syntax.DID("did:web:example.com"))
	if !errors.Is(err, ErrDIDResolutionFailed) {
		t.Fatalf("expected resolution failure, got %v", err)
	}
	var response *DIDHTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503, got %v", err)
	}
}
