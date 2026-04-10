package clash

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
	vendorlog "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net"
	"strings"
)

func init() {
	patch()
}

// patch is used to fix the logger exit function
func patch() {
	logger := vendorlog.StandardLogger()
	logger.ExitFunc = func(code int) {}
}
func pickResolvedProxyServerIP(ips []net.IP) (string, bool) {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), true
		}
	}
	for _, ip := range ips {
		if ip.To16() != nil {
			return ip.String(), true
		}
	}
	return "", false
}

func setStringIfMissing(payload map[string]any, key string, val string) {
	if payload == nil || strings.TrimSpace(val) == "" {
		return
	}
	if existing, ok := payload[key]; ok {
		if s, sok := existing.(string); sok && strings.TrimSpace(s) != "" {
			return
		}
	}
	payload[key] = val
}

func applyMihomoDNSForProxyServer(payload map[string]any, dnsServers []string) {
	if len(dnsServers) == 0 || payload == nil {
		return
	}

	rawServer, ok := payload["server"]
	if !ok {
		return
	}
	server, ok := rawServer.(string)
	if !ok {
		return
	}
	server = strings.TrimSpace(server)
	if server == "" {
		return
	}
	if net.ParseIP(server) != nil {
		return
	}
	utils.DLogf("Mihomo DNS proxy server resolve start | server=%q | dnsServers=%d", server, len(dnsServers))

	ips, matched, err := utils.LookupByMihomoDNSServers(server, dnsServers)
	if !matched {
		utils.DLogf("Mihomo DNS proxy server resolve skip | server=%q | reason=no mihomo token", server)
		return
	}
	if err != nil {
		utils.DLogf("Mihomo DNS resolve proxy server failed | server=%q | err=%v", server, err)
		return
	}

	resolvedIP, ok := pickResolvedProxyServerIP(ips)
	if !ok {
		utils.DLogf("Mihomo DNS resolved proxy server but no IP selected | server=%q", server)
		return
	}

	payload["server"] = resolvedIP
	// Preserve original domain for TLS/SNI-sensitive protocols.
	setStringIfMissing(payload, "sni", server)
	setStringIfMissing(payload, "servername", server)
	utils.DLogf("Mihomo DNS proxy server rewritten | domain=%q | ip=%q | sni=%v | servername=%v", server, resolvedIP, payload["sni"], payload["servername"])
}

func parseProxy(proxyName, proxyPayload string, dnsServers []string) constant.Proxy {
	var payload map[string]any
	if err := yaml.Unmarshal([]byte(proxyPayload), &payload); err != nil {
		utils.DLogf("Vendor Parser | Parse clash profile yaml error, error=%v", err.Error())
		return nil
	}
	applyMihomoDNSForProxyServer(payload, dnsServers)
	proxy, err := adapter.ParseProxy(payload)

	if err != nil {
		utils.DLogf("Vendor Parser | Parse clash profile error, error=%v", err.Error())
		return nil
	}

	return proxy
}

func extractFirstProxy(proxyName, proxyPayload string) constant.Proxy {
	return extractFirstProxyWithDNS(proxyName, proxyPayload, nil)
}

func extractFirstProxyWithDNS(proxyName, proxyPayload string, dnsServers []string) constant.Proxy {
	proxy := parseProxy(proxyName, proxyPayload, dnsServers)
	if proxy == nil {
		return nil
	}
	if interfaces.Parse(proxy.Type().String()) != interfaces.ProxyInvalid {
		return proxy
	}

	return nil
}
