package tests

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airportr/miaospeed/utils"
	"github.com/miekg/dns"
)

func buildDoHResponse(t *testing.T, req *http.Request) []byte {
	t.Helper()

	encoded := req.URL.Query().Get("dns")
	if encoded == "" {
		t.Fatalf("missing dns query parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode dns query: %v", err)
	}
	var query dns.Msg
	if err := query.Unpack(raw); err != nil {
		t.Fatalf("unpack dns query: %v", err)
	}

	resp := dns.Msg{}
	resp.SetReply(&query)
	for _, question := range query.Question {
		switch question.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("203.0.113.7").To4(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::7"),
			})
		}
	}

	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}
	return packed
}

func containsIP(ips []net.IP, target string) bool {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(targetIP) {
			return true
		}
	}
	return false
}

func TestDohLookup_UsesCustomEndpointPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/custom/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildDoHResponse(t, r))
	}))
	defer server.Close()

	ips := utils.DohLookup("example.com", server.URL+"/custom/dns-query")

	if !containsIP(ips, "203.0.113.7") {
		t.Fatalf("expected A record in DoH response, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::7") {
		t.Fatalf("expected AAAA record in DoH response, got %v", ips)
	}
}

func TestDohLookup_RequestFailureDoesNotPanic(t *testing.T) {
	ips := utils.DohLookup("example.com", "http://127.0.0.1:1/dns-query")
	if len(ips) != 0 {
		t.Fatalf("expected no IPs on request failure, got %v", ips)
	}
}
