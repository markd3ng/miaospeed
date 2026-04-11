package utils

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConst "github.com/metacubex/mihomo/constant"
	mihomoDNS "github.com/metacubex/mihomo/dns"
	mihomoExecutor "github.com/metacubex/mihomo/hub/executor"
)

const mihomoDNSServerPrefix = "mihomo://"

type MihomoDNSClient struct {
	resolver       *mihomoDNS.Resolver
	proxyResolver  *mihomoDNS.Resolver
	directResolver *mihomoDNS.Resolver
	ipv6           bool
	dnsTrace       string
}

type mihomoDNSCacheEntry struct {
	modTime time.Time
	size    int64
	client  *MihomoDNSClient
}

var (
	mihomoDNSFileCache   sync.Map
	mihomoDNSFileCacheMu sync.Mutex

	mihomoDNSContentCache   sync.Map
	mihomoDNSContentCacheMu sync.Mutex
)

func parseMihomoDNSServer(server string) (configPath string, ok bool) {
	server = strings.TrimSpace(server)
	if len(server) < len(mihomoDNSServerPrefix) {
		return "", false
	}
	if !strings.EqualFold(server[:len(mihomoDNSServerPrefix)], mihomoDNSServerPrefix) {
		return "", false
	}
	configPath = strings.TrimSpace(server[len(mihomoDNSServerPrefix):])
	if configPath == "" {
		return "", false
	}
	return configPath, true
}

func parseMihomoDNSServerBase64(server string) (configContent []byte, matched bool, err error) {
	encoded, ok := parseMihomoDNSServer(server)
	if !ok {
		return nil, false, nil
	}

	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, decoder := range decoders {
		decoded, decodeErr := decoder.DecodeString(encoded)
		if decodeErr == nil {
			if len(decoded) == 0 {
				return nil, true, fmt.Errorf("empty base64 mihomo dns config")
			}
			return decoded, true, nil
		}
	}

	return nil, true, fmt.Errorf("invalid base64 mihomo dns config")
}

func normalizeMihomoConfigPath(configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return "", fmt.Errorf("empty config path")
	}

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve config path=%q failed: %w", configPath, err)
	}
	return absPath, nil
}

func sanitizeMihomoNameServers(nameServers []mihomoDNS.NameServer) []mihomoDNS.NameServer {
	if len(nameServers) == 0 {
		return nil
	}
	cleaned := make([]mihomoDNS.NameServer, 0, len(nameServers))
	for _, ns := range nameServers {
		if strings.EqualFold(strings.TrimSpace(ns.Net), "system") {
			continue
		}
		// Ignore any `#proxy` tag (such as #DIRECT/#RULES/custom name) for our standalone DNS lookup path.
		// Otherwise mihomo DNS dialer may treat unknown proxy name as interface and fail with "interface not found".
		ns.ProxyName = ""
		ns.ProxyAdapter = nil
		cleaned = append(cleaned, ns)
	}
	return cleaned
}

func formatMihomoNameServer(ns mihomoDNS.NameServer) string {
	addr := strings.TrimSpace(ns.Addr)
	netType := strings.TrimSpace(ns.Net)
	if netType == "" {
		netType = "udp"
	}
	if strings.Contains(addr, "://") {
		netType = ""
	}
	base := addr
	if netType != "" {
		base = fmt.Sprintf("%s://%s", netType, addr)
	}
	if ns.ProxyName != "" {
		base = fmt.Sprintf("%s#proxy=%s", base, ns.ProxyName)
	}
	if len(ns.Params) > 0 {
		keys := make([]string, 0, len(ns.Params))
		for k := range ns.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		params := make([]string, 0, len(keys))
		for _, k := range keys {
			params = append(params, fmt.Sprintf("%s=%s", k, ns.Params[k]))
		}
		base = fmt.Sprintf("%s{%s}", base, strings.Join(params, ","))
	}
	return base
}

func formatMihomoNameServerList(nameServers []mihomoDNS.NameServer) string {
	if len(nameServers) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(nameServers))
	for _, ns := range nameServers {
		parts = append(parts, formatMihomoNameServer(ns))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func buildMihomoDNSTrace(dnsCfg *mihomoConfig.DNS) string {
	if dnsCfg == nil {
		return "dns=nil"
	}
	return fmt.Sprintf(
		"ipv6=%t main=%s fallback=%s default=%s proxy=%s direct=%s policy=%d proxyPolicy=%d",
		dnsCfg.IPv6,
		formatMihomoNameServerList(dnsCfg.NameServer),
		formatMihomoNameServerList(dnsCfg.Fallback),
		formatMihomoNameServerList(dnsCfg.DefaultNameserver),
		formatMihomoNameServerList(dnsCfg.ProxyServerNameserver),
		formatMihomoNameServerList(dnsCfg.DirectNameServer),
		len(dnsCfg.NameServerPolicy),
		len(dnsCfg.ProxyServerPolicy),
	)
}

func sanitizeMihomoPolicies(policies []mihomoDNS.Policy) []mihomoDNS.Policy {
	if len(policies) == 0 {
		return nil
	}
	cleaned := make([]mihomoDNS.Policy, 0, len(policies))
	for _, policy := range policies {
		policy.NameServers = sanitizeMihomoNameServers(policy.NameServers)
		if len(policy.NameServers) == 0 {
			continue
		}
		cleaned = append(cleaned, policy)
	}
	return cleaned
}

// sanitizeMihomoDNSConfigForLookup forces real-ip resolution behavior for this project.
// User-provided configs may contain fake-ip/system resolver fields that are not desired here.
func sanitizeMihomoDNSConfigForLookup(dnsCfg *mihomoConfig.DNS) {
	if dnsCfg == nil {
		return
	}

	if dnsCfg.EnhancedMode == mihomoConst.DNSFakeIP {
		DLogf("Mihomo DNS config has enhanced-mode=fake-ip; forcing real-ip lookup mode")
	}
	dnsCfg.EnhancedMode = mihomoConst.DNSNormal
	dnsCfg.FakeIPPool = nil
	dnsCfg.FakeIPPool6 = nil
	dnsCfg.FakeIPSkipper = nil
	dnsCfg.FakeIPTTL = 0

	dnsCfg.NameServer = sanitizeMihomoNameServers(dnsCfg.NameServer)
	dnsCfg.Fallback = sanitizeMihomoNameServers(dnsCfg.Fallback)
	dnsCfg.DefaultNameserver = sanitizeMihomoNameServers(dnsCfg.DefaultNameserver)
	dnsCfg.ProxyServerNameserver = sanitizeMihomoNameServers(dnsCfg.ProxyServerNameserver)
	dnsCfg.DirectNameServer = sanitizeMihomoNameServers(dnsCfg.DirectNameServer)
	dnsCfg.NameServerPolicy = sanitizeMihomoPolicies(dnsCfg.NameServerPolicy)
	dnsCfg.ProxyServerPolicy = sanitizeMihomoPolicies(dnsCfg.ProxyServerPolicy)

	if len(dnsCfg.NameServer) == 0 {
		switch {
		case len(dnsCfg.DefaultNameserver) > 0:
			dnsCfg.NameServer = append([]mihomoDNS.NameServer(nil), dnsCfg.DefaultNameserver...)
		case len(dnsCfg.Fallback) > 0:
			dnsCfg.NameServer = append([]mihomoDNS.NameServer(nil), dnsCfg.Fallback...)
		}
		if len(dnsCfg.NameServer) == 0 {
			DWarnf("Mihomo DNS config has no usable nameserver after sanitization; will fallback to system resolver at lookup stage")
		}
	}
}

func lookupBySystemResolver(domain string) ([]net.IP, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip found by system resolver for domain=%q", domain)
	}
	return ips, nil
}

type mihomoResolverCandidate struct {
	name     string
	resolver *mihomoDNS.Resolver
}

func appendMihomoResolverCandidate(candidates []mihomoResolverCandidate, seen map[*mihomoDNS.Resolver]struct{}, name string, resolver *mihomoDNS.Resolver) []mihomoResolverCandidate {
	if resolver == nil || !resolver.Invalid() {
		return candidates
	}
	if _, ok := seen[resolver]; ok {
		return candidates
	}
	seen[resolver] = struct{}{}
	return append(candidates, mihomoResolverCandidate{name: name, resolver: resolver})
}

func newMihomoDNSClientFromConfigBytes(configContent []byte) (*MihomoDNSClient, error) {
	if len(configContent) == 0 {
		return nil, fmt.Errorf("empty mihomo config")
	}

	cfg, err := mihomoExecutor.ParseWithBytes(configContent)
	if err != nil {
		return nil, fmt.Errorf("parse mihomo config failed: %w", err)
	}

	if cfg == nil || cfg.DNS == nil {
		return nil, fmt.Errorf("mihomo config has no dns section")
	}
	if !cfg.DNS.Enable {
		return nil, fmt.Errorf("mihomo dns is disabled in config")
	}
	sanitizeMihomoDNSConfigForLookup(cfg.DNS)
	dnsTrace := buildMihomoDNSTrace(cfg.DNS)

	ipv6 := cfg.DNS.IPv6
	if cfg.General != nil {
		ipv6 = ipv6 && cfg.General.IPv6
	}

	resolvers := mihomoDNS.NewResolver(mihomoDNS.Config{
		Main:                 cfg.DNS.NameServer,
		Fallback:             cfg.DNS.Fallback,
		IPv6:                 ipv6,
		IPv6Timeout:          cfg.DNS.IPv6Timeout,
		FallbackIPFilter:     cfg.DNS.FallbackIPFilter,
		FallbackDomainFilter: cfg.DNS.FallbackDomainFilter,
		Default:              cfg.DNS.DefaultNameserver,
		Policy:               cfg.DNS.NameServerPolicy,
		ProxyServer:          cfg.DNS.ProxyServerNameserver,
		ProxyServerPolicy:    cfg.DNS.ProxyServerPolicy,
		DirectServer:         cfg.DNS.DirectNameServer,
		DirectFollowPolicy:   cfg.DNS.DirectFollowPolicy,
		CacheAlgorithm:       cfg.DNS.CacheAlgorithm,
		CacheMaxSize:         cfg.DNS.CacheMaxSize,
	})

	if resolvers.Resolver == nil || !resolvers.Resolver.Invalid() {
		return nil, fmt.Errorf("mihomo dns resolver is unavailable")
	}

	return &MihomoDNSClient{
		resolver:       resolvers.Resolver,
		proxyResolver:  resolvers.ProxyResolver,
		directResolver: resolvers.DirectResolver,
		ipv6:           ipv6,
		dnsTrace:       dnsTrace,
	}, nil
}

// NewMihomoDNSClientFromConfigBytes creates a DNS client from in-memory mihomo config bytes.
func NewMihomoDNSClientFromConfigBytes(configContent []byte) (*MihomoDNSClient, error) {
	return newMihomoDNSClientFromConfigBytes(configContent)
}

// NewMihomoDNSClientFromConfigFile creates a DNS client from a mihomo config file.
func NewMihomoDNSClientFromConfigFile(configPath string) (*MihomoDNSClient, error) {
	absPath, err := normalizeMihomoConfigPath(configPath)
	if err != nil {
		return nil, err
	}

	configContent, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read mihomo config path=%q failed: %w", absPath, err)
	}

	return newMihomoDNSClientFromConfigBytes(configContent)
}

func getCachedMihomoDNSClientFromConfigFile(configPath string) (*MihomoDNSClient, error) {
	absPath, err := normalizeMihomoConfigPath(configPath)
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat mihomo config path=%q failed: %w", absPath, err)
	}

	mihomoDNSFileCacheMu.Lock()
	defer mihomoDNSFileCacheMu.Unlock()

	if cacheEntryAny, ok := mihomoDNSFileCache.Load(absPath); ok {
		if cacheEntry, ok := cacheEntryAny.(*mihomoDNSCacheEntry); ok && cacheEntry != nil &&
			cacheEntry.client != nil &&
			cacheEntry.size == fileInfo.Size() &&
			cacheEntry.modTime.Equal(fileInfo.ModTime()) {
			DLogf("Mihomo DNS file cache hit | path=%q", absPath)
			return cacheEntry.client, nil
		}
	}
	DLogf("Mihomo DNS file cache miss | path=%q", absPath)

	client, err := NewMihomoDNSClientFromConfigFile(absPath)
	if err != nil {
		return nil, err
	}

	mihomoDNSFileCache.Store(absPath, &mihomoDNSCacheEntry{
		modTime: fileInfo.ModTime(),
		size:    fileInfo.Size(),
		client:  client,
	})

	return client, nil
}

func mihomoConfigContentKey(configContent []byte) (string, error) {
	if len(configContent) == 0 {
		return "", fmt.Errorf("empty mihomo config")
	}
	sum := sha256.Sum256(configContent)
	return fmt.Sprintf("%x", sum[:]), nil
}

func getCachedMihomoDNSClientFromConfigBytes(configContent []byte) (*MihomoDNSClient, error) {
	cacheKey, err := mihomoConfigContentKey(configContent)
	if err != nil {
		return nil, err
	}

	mihomoDNSContentCacheMu.Lock()
	defer mihomoDNSContentCacheMu.Unlock()

	if cachedClientAny, ok := mihomoDNSContentCache.Load(cacheKey); ok {
		if cachedClient, ok := cachedClientAny.(*MihomoDNSClient); ok && cachedClient != nil {
			DLogf("Mihomo DNS content cache hit | key=%s", cacheKey)
			return cachedClient, nil
		}
	}
	DLogf("Mihomo DNS content cache miss | key=%s", cacheKey)

	client, err := NewMihomoDNSClientFromConfigBytes(configContent)
	if err != nil {
		return nil, err
	}

	mihomoDNSContentCache.Store(cacheKey, client)
	return client, nil
}

func (c *MihomoDNSClient) lookupWithResolver(ctx context.Context, domain string, resolver *mihomoDNS.Resolver) ([]net.IP, error) {
	if c == nil || resolver == nil || !resolver.Invalid() {
		return nil, fmt.Errorf("mihomo dns client is not initialized")
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	var (
		addrs []netip.Addr
		err   error
	)
	if c.ipv6 {
		addrs, err = resolver.LookupIP(ctx, domain)
	} else {
		addrs, err = resolver.LookupIPv4(ctx, domain)
	}
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if !c.ipv6 && !addr.Is4() {
			continue
		}
		ip := net.IP(addr.AsSlice())
		ipKey := ip.String()
		if _, ok := seen[ipKey]; ok {
			continue
		}
		seen[ipKey] = struct{}{}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip found for domain=%q", domain)
	}

	return ips, nil
}

func (c *MihomoDNSClient) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return c.lookupWithResolver(ctx, domain, c.resolver)
}

func (c *MihomoDNSClient) lookupIPsWithPreference(ctx context.Context, domain string, preferProxy bool) (ips []net.IP, resolverName string, err error) {
	if c == nil {
		return nil, "", fmt.Errorf("mihomo dns client is not initialized")
	}

	candidates := make([]mihomoResolverCandidate, 0, 3)
	seen := make(map[*mihomoDNS.Resolver]struct{}, 3)
	if preferProxy {
		candidates = appendMihomoResolverCandidate(candidates, seen, "proxy", c.proxyResolver)
		candidates = appendMihomoResolverCandidate(candidates, seen, "main", c.resolver)
		candidates = appendMihomoResolverCandidate(candidates, seen, "direct", c.directResolver)
	} else {
		candidates = appendMihomoResolverCandidate(candidates, seen, "main", c.resolver)
		candidates = appendMihomoResolverCandidate(candidates, seen, "proxy", c.proxyResolver)
		candidates = appendMihomoResolverCandidate(candidates, seen, "direct", c.directResolver)
	}

	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("mihomo dns has no available resolver")
	}

	resolverErrs := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ips, err = c.lookupWithResolver(ctx, domain, candidate.resolver)
		if err == nil && len(ips) > 0 {
			return ips, candidate.name, nil
		}
		if err != nil {
			resolverErrs = append(resolverErrs, fmt.Sprintf("%s resolver: %v", candidate.name, err))
		} else {
			resolverErrs = append(resolverErrs, fmt.Sprintf("%s resolver: no ip found", candidate.name))
		}
	}

	if len(resolverErrs) > 0 {
		return nil, "", fmt.Errorf("all mihomo resolvers failed: %s", strings.Join(resolverErrs, " | "))
	}
	return nil, "", fmt.Errorf("mihomo dns has no ip for domain=%q", domain)
}

func lookupDomainByMihomoClient(domain string, source string, client *MihomoDNSClient, preferProxy bool) ([]net.IP, error) {
	if client == nil {
		ips, fallbackErr := lookupBySystemResolver(domain)
		if fallbackErr == nil {
			DWarnf("Mihomo DNS lookup done | source=%s | domain=%q | dns=system_fallback | resolver=system | result=%v | reason=nil-client", source, domain, ips)
			return ips, nil
		}
		DWarnf("Mihomo DNS lookup failed | source=%s | domain=%q | err=nil-client | systemErr=%v", source, domain, fallbackErr)
		return nil, fmt.Errorf("nil mihomo dns client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, resolverName, lookupErr := client.lookupIPsWithPreference(ctx, domain, preferProxy)
	if lookupErr == nil {
		DWarnf("Mihomo DNS lookup done | source=%s | domain=%q | resolver=%s | dns=%s | result=%v", source, domain, resolverName, client.dnsTrace, ips)
		return ips, nil
	}

	fallbackIPs, fallbackErr := lookupBySystemResolver(domain)
	if fallbackErr == nil {
		DWarnf("Mihomo DNS lookup done | source=%s | domain=%q | dns=system_fallback | resolver=system | result=%v | reason=%v", source, domain, fallbackIPs, lookupErr)
		return fallbackIPs, nil
	}

	DWarnf("Mihomo DNS lookup failed | source=%s | domain=%q | dns=%s | err=%v | systemErr=%v", source, domain, client.dnsTrace, lookupErr, fallbackErr)
	return nil, lookupErr
}

// LookupByMihomoConfigFile resolves a domain with DNS settings from a mihomo config file.
func LookupByMihomoConfigFile(configPath string, domain string) ([]net.IP, error) {
	client, err := getCachedMihomoDNSClientFromConfigFile(configPath)
	if err != nil {
		ips, fallbackErr := lookupBySystemResolver(domain)
		if fallbackErr == nil {
			DWarnf("Mihomo DNS lookup done | source=config_file | domain=%q | dns=system_fallback | result=%v | reason=%v", domain, ips, err)
			return ips, nil
		}
		DWarnf("Mihomo DNS lookup failed | source=config_file | domain=%q | err=%v | systemErr=%v", domain, err, fallbackErr)
		return nil, err
	}
	return lookupDomainByMihomoClient(domain, "config_file", client, true)
}

// LookupByMihomoConfigBytes resolves a domain with DNS settings from in-memory mihomo config bytes.
func LookupByMihomoConfigBytes(configContent []byte, domain string) ([]net.IP, error) {
	client, err := getCachedMihomoDNSClientFromConfigBytes(configContent)
	if err != nil {
		ips, fallbackErr := lookupBySystemResolver(domain)
		if fallbackErr == nil {
			DWarnf("Mihomo DNS lookup done | source=config_bytes | domain=%q | dns=system_fallback | result=%v | reason=%v", domain, ips, err)
			return ips, nil
		}
		DWarnf("Mihomo DNS lookup failed | source=config_bytes | domain=%q | err=%v | systemErr=%v", domain, err, fallbackErr)
		return nil, err
	}
	return lookupDomainByMihomoClient(domain, "config_bytes", client, true)
}

// LookupByMihomoDNSServers resolves a domain by searching mihomo:// tokens in dns servers list.
// It returns matched=false when there is no mihomo:// token.
func LookupByMihomoDNSServers(domain string, queryServers []string) (ips []net.IP, matched bool, err error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, false, fmt.Errorf("empty domain")
	}
	DLogf("Mihomo DNS lookup start | domain=%q | queryServers=%d", domain, len(queryServers))

	var lastErr error
	for idx, rawServer := range queryServers {
		server := strings.TrimSpace(rawServer)
		if server == "" {
			continue
		}
		configContent, tokenMatched, parseErr := parseMihomoDNSServerBase64(server)
		if !tokenMatched {
			continue
		}

		matched = true
		DLogf("Mihomo DNS token matched | domain=%q | index=%d", domain, idx)
		if parseErr != nil {
			DLogf("Mihomo DNS token parse error | domain=%q | index=%d | err=%v", domain, idx, parseErr)
			lastErr = parseErr
			continue
		}

		client, clientErr := getCachedMihomoDNSClientFromConfigBytes(configContent)
		if clientErr != nil {
			DLogf("Mihomo DNS token client init failed | domain=%q | index=%d | err=%v", domain, idx, clientErr)
			lastErr = clientErr
			continue
		}
		ips, err = lookupDomainByMihomoClient(domain, fmt.Sprintf("token[%d]", idx), client, true)
		if err != nil {
			DLogf("Mihomo DNS token lookup failed | domain=%q | index=%d | err=%v", domain, idx, err)
			lastErr = err
			continue
		}
		if len(ips) > 0 {
			DLogf("Mihomo DNS token lookup success | domain=%q | index=%d | ips=%v", domain, idx, ips)
			return ips, true, nil
		}
	}

	if !matched {
		DLogf("Mihomo DNS lookup skip | domain=%q | reason=no mihomo token", domain)
		return nil, false, nil
	}
	if lastErr != nil {
		DLogf("Mihomo DNS lookup exhausted | domain=%q | err=%v", domain, lastErr)
		return nil, true, lastErr
	}
	DLogf("Mihomo DNS lookup exhausted | domain=%q | err=no ip found", domain)
	return nil, true, fmt.Errorf("mihomo dns has no ip for domain=%q", domain)
}
