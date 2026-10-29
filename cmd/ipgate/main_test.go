package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		"":               "http://127.0.0.1:8080/healthz",
		":8080":          "http://127.0.0.1:8080/healthz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/healthz",
		"[::]:8080":      "http://[::1]:8080/healthz",
		"10.0.0.5:8080":  "http://10.0.0.5:8080/healthz",
		"localhost:1234": "http://localhost:1234/healthz",
	} {
		got, err := healthURL(in)
		if err != nil || got != want {
			t.Errorf("healthURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := healthURL("nonsense"); err == nil {
		t.Error("expected error for bad LISTEN_ADDR")
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ok\n"))
	}))
	defer ok.Close()
	if err := healthcheck(ok.Listener.Addr().String(), time.Second); err != nil {
		t.Errorf("healthy server: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 500)
	}))
	defer bad.Close()
	if err := healthcheck(bad.Listener.Addr().String(), time.Second); err == nil {
		t.Error("unhealthy server reported healthy")
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if err := healthcheck(addr, time.Second); err == nil {
		t.Error("closed port reported healthy")
	}
}
