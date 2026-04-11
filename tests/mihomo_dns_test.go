package tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/airportr/miaospeed/utils"
	mdns "github.com/miekg/dns"
)

func startLocalDNSServerWithRecords(t *testing.T, ipv4 string, ipv6 string) (addr string, closeFn func()) {
	t.Helper()
	a := net.ParseIP(ipv4).To4()
	if a == nil {
		t.Fatalf("invalid IPv4 for local dns server: %q", ipv4)
	}
	aaaa := net.ParseIP(ipv6)
	if aaaa == nil || aaaa.To16() == nil {
		t.Fatalf("invalid IPv6 for local dns server: %q", ipv6)
	}

	handler := mdns.NewServeMux()
	handler.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := &mdns.Msg{}
		resp.SetReply(req)

		for _, question := range req.Question {
			switch question.Qtype {
			case mdns.TypeA:
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
					A:   a,
				})
			case mdns.TypeAAAA:
				resp.Answer = append(resp.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 30},
					AAAA: aaaa,
				})
			}
		}

		_ = w.WriteMsg(resp)
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local dns server: %v", err)
	}

	server := &mdns.Server{
		PacketConn: packetConn,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()

	return packetConn.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	}
}

func startLocalDNSServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	return startLocalDNSServerWithRecords(t, "198.51.100.42", "2001:db8::42")
}

func writeMihomoDNSConfig(t *testing.T, nameServer string) string {
	t.Helper()

	configContent := buildMihomoDNSConfigBytes(nameServer)

	configPath := filepath.Join(t.TempDir(), "mihomo_dns.yaml")
	if err := os.WriteFile(configPath, configContent, 0o600); err != nil {
		t.Fatalf("write mihomo dns config: %v", err)
	}

	return configPath
}

func buildMihomoDNSConfigBytes(nameServer string) []byte {
	return []byte(fmt.Sprintf(`dns:
  enable: true
  ipv6: true
  nameserver:
    - %s
  default-nameserver:
    - 127.0.0.1
`, nameServer))
}

func TestLookupByMihomoConfigFile(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configPath := writeMihomoDNSConfig(t, nameServer)
	ips, err := utils.LookupByMihomoConfigFile(configPath, "example.com")
	if err != nil {
		t.Fatalf("lookup by mihomo config file error: %v", err)
	}

	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from mihomo dns lookup, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from mihomo dns lookup, got %v", ips)
	}
}

func TestDNSLookuper_SupportsMihomoServerBase64Token(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configBytes := buildMihomoDNSConfigBytes(nameServer)
	token := "mihomo://" + base64.StdEncoding.EncodeToString(configBytes)
	ips := utils.DNSLookuper("example.com", []string{token})

	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from DNSLookuper mihomo token, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from DNSLookuper mihomo token, got %v", ips)
	}
}

func TestLookupByMihomoConfigBytes(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configBytes := buildMihomoDNSConfigBytes(nameServer)
	ips, err := utils.LookupByMihomoConfigBytes(configBytes, "example.com")
	if err != nil {
		t.Fatalf("lookup by mihomo config bytes error: %v", err)
	}

	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from mihomo dns bytes lookup, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from mihomo dns bytes lookup, got %v", ips)
	}
}

func TestDNSLookuper_MihomoPathTokenIsIgnored(t *testing.T) {
	ips := utils.DNSLookuper("example.com", []string{"mihomo://D:/path/to/config.yaml"})
	if len(ips) != 0 {
		t.Fatalf("expected no IPs for non-base64 mihomo token, got %v", ips)
	}
}

func TestLookupByMihomoDNSServers_Base64Token(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configBytes := buildMihomoDNSConfigBytes(nameServer)
	token := "mihomo://" + base64.StdEncoding.EncodeToString(configBytes)
	ips, matched, err := utils.LookupByMihomoDNSServers("example.com", []string{"8.8.8.8", token})
	if err != nil {
		t.Fatalf("lookup by mihomo dns servers failed: %v", err)
	}
	if !matched {
		t.Fatalf("expected matched=true when mihomo token exists")
	}
	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from mihomo token lookup, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from mihomo token lookup, got %v", ips)
	}
}

func TestLookupByMihomoDNSServers_PrefersProxyServerResolver(t *testing.T) {
	mainNameServer, closeMain := startLocalDNSServerWithRecords(t, "203.0.113.10", "2001:db8::10")
	defer closeMain()

	proxyNameServer, closeProxy := startLocalDNSServerWithRecords(t, "198.51.100.42", "2001:db8::42")
	defer closeProxy()

	configBytes := []byte(fmt.Sprintf(`dns:
  enable: true
  ipv6: true
  nameserver:
    - %s
  proxy-server-nameserver:
    - %s
  default-nameserver:
    - 127.0.0.1
`, mainNameServer, proxyNameServer))
	token := "mihomo://" + base64.StdEncoding.EncodeToString(configBytes)

	ips, matched, err := utils.LookupByMihomoDNSServers("example.com", []string{token})
	if err != nil {
		t.Fatalf("lookup by mihomo dns servers with proxy resolver failed: %v", err)
	}
	if !matched {
		t.Fatalf("expected matched=true when mihomo token exists")
	}
	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from proxy-server-nameserver, got %v", ips)
	}
	if containsIP(ips, "203.0.113.10") {
		t.Fatalf("expected not to use main nameserver result when proxy resolver is available, got %v", ips)
	}
}

func TestLookupByMihomoDNSServers_NoToken(t *testing.T) {
	ips, matched, err := utils.LookupByMihomoDNSServers("example.com", []string{"8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Fatalf("expected no error when no mihomo token, got %v", err)
	}
	if matched {
		t.Fatalf("expected matched=false when no mihomo token")
	}
	if len(ips) != 0 {
		t.Fatalf("expected empty ips when no mihomo token, got %v", ips)
	}
}

func TestLookupByMihomoConfigBytes_FakeIPAndSystemNameserverSanitized(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configBytes := []byte(fmt.Sprintf(`dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  ipv6: true
  nameserver:
    - system
  default-nameserver:
    - "%s"
`, nameServer))

	ips, err := utils.LookupByMihomoConfigBytes(configBytes, "example.com")
	if err != nil {
		t.Fatalf("lookup by sanitized mihomo config bytes error: %v", err)
	}
	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from sanitized mihomo lookup, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from sanitized mihomo lookup, got %v", ips)
	}
}

func TestLookupByMihomoConfigBytes_NameserverProxyTagSanitized(t *testing.T) {
	nameServer, closeFn := startLocalDNSServer(t)
	defer closeFn()

	configBytes := []byte(fmt.Sprintf(`dns:
  enable: true
  ipv6: true
  nameserver:
    - "udp://%s#DIRECT"
  default-nameserver:
    - 127.0.0.1
`, nameServer))

	ips, err := utils.LookupByMihomoConfigBytes(configBytes, "example.com")
	if err != nil {
		t.Fatalf("lookup with nameserver #DIRECT tag should succeed after sanitization: %v", err)
	}
	if !containsIP(ips, "198.51.100.42") {
		t.Fatalf("expected A record from sanitized nameserver #DIRECT lookup, got %v", ips)
	}
	if !containsIP(ips, "2001:db8::42") {
		t.Fatalf("expected AAAA record from sanitized nameserver #DIRECT lookup, got %v", ips)
	}
}

func TestLookupByMihomoConfigBytes_OvalyraaCompareDirectLive(t *testing.T) {
	if os.Getenv("MIAOSPEED_RUN_LIVE_DNS_TEST") != "1" {
		t.Skip("skip live DNS test; set MIAOSPEED_RUN_LIVE_DNS_TEST=1 to enable")
	}

	const serverDomain = "97123fh.jnonwf.sbs"
	configBytes := []byte(`dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  respect-rules: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
  fake-ip-filter: ['*', +.lan, +.local]
  default-nameserver: [https://223.5.5.5/dns-query#DIRECT, https://1.12.12.12/dns-query#DIRECT]
  direct-nameserver: [https://223.5.5.5/dns-query#DIRECT, https://1.12.12.12/dns-query#DIRECT]
  proxy-server-nameserver: 
    - https://wrecking7857.com:44443/dns-query/b9587e89-d635-497b-85b0-40d6db2425a1
    - https://carrousel6917.com:44443/dns-query/b9587e89-d635-497b-85b0-40d6db2425a1
    - https://simmering3378.com:443/dns-query/b9587e89-d635-497b-85b0-40d6db2425a1
  nameserver: [https://1.1.1.1/dns-query#Switch, https://8.8.8.8/dns-query#Switch]
`)

	ipsByConfig, err := utils.LookupByMihomoConfigBytes(configBytes, serverDomain)
	if err != nil {
		t.Fatalf("lookup by mihomo config bytes (ovalyraa live) error: %v", err)
	}
	if len(ipsByConfig) == 0 {
		t.Fatalf("expected non-empty IP list via mihomo config for %s", serverDomain)
	}

	configPath := filepath.Join(t.TempDir(), "mihomo_ovalyraa.yaml")
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		t.Fatalf("write ovalyraa mihomo config: %v", err)
	}

	ipsByFile, err := utils.LookupByMihomoConfigFile(configPath, serverDomain)
	if err != nil {
		t.Fatalf("lookup by mihomo config file (ovalyraa live) error: %v", err)
	}
	if len(ipsByFile) == 0 {
		t.Fatalf("expected non-empty IP list via config file for %s", serverDomain)
	}

	directIPs, directErr := net.LookupIP(serverDomain)
	if directErr != nil {
		t.Logf("direct lookup (without mihomo config) failed for %s: %v", serverDomain, directErr)
	} else {
		t.Logf("direct lookup (without mihomo config) -> %v", directIPs)
	}

	t.Logf("mihomo lookup by config bytes -> %v", ipsByConfig)
	t.Logf("mihomo lookup by config file -> %v", ipsByFile)
}
