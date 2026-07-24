package tests

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/vendors"
)

func TestRequestUnsafeFollowsRedirectAcrossHostsWithVendor(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/payload" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("from-target"))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, target.URL+"/payload", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("wrong-host"))
	}))
	defer source.Close()

	v := vendors.Find(interfaces.VendorLocal).Build("local", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, redirects, err := vendors.RequestUnsafe(ctx, v, &interfaces.RequestOptions{
		URL: source.URL,
	})
	if err != nil {
		t.Fatalf("RequestUnsafe returned error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("cannot read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%q", http.StatusOK, resp.StatusCode, string(body))
	}
	if string(body) != "from-target" {
		t.Fatalf("expected body %q, got %q", "from-target", string(body))
	}
	if len(redirects) != 1 {
		t.Fatalf("expected 1 redirect record, got %d: %v", len(redirects), redirects)
	}
	if redirects[0] != target.URL+"/payload" {
		t.Fatalf("expected redirect target %q, got %q", target.URL+"/payload", redirects[0])
	}
}

func TestRequestUnsafeFollowsRedirectAcrossHostsWithoutVendor(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/payload" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("from-target"))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/payload", http.StatusFound)
	}))
	defer source.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, redirects, err := vendors.RequestUnsafe(ctx, nil, &interfaces.RequestOptions{
		URL: source.URL,
	})
	if err != nil {
		t.Fatalf("RequestUnsafe returned error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("cannot read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%q", http.StatusOK, resp.StatusCode, string(body))
	}
	if string(body) != "from-target" {
		t.Fatalf("expected body %q, got %q", "from-target", string(body))
	}
	if len(redirects) != 1 {
		t.Fatalf("expected 1 redirect record, got %d: %v", len(redirects), redirects)
	}
}

func TestRequestUnsafeNoRedirStopsAtFirstResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from-target"))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/payload", http.StatusFound)
	}))
	defer source.Close()

	v := vendors.Find(interfaces.VendorLocal).Build("local", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, redirects, err := vendors.RequestUnsafe(ctx, v, &interfaces.RequestOptions{
		URL:     source.URL,
		NoRedir: true,
	})
	if err != nil {
		t.Fatalf("RequestUnsafe returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc == "" {
		t.Fatalf("expected Location header on redirect response")
	}
	if len(redirects) != 0 {
		t.Fatalf("expected 0 redirect records when NoRedir=true, got %d: %v", len(redirects), redirects)
	}
}
