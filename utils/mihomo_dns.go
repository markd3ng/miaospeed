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
	"strings"
	"sync"
	"time"

	mihomoDNS "github.com/metacubex/mihomo/dns"
	mihomoExecutor "github.com/metacubex/mihomo/hub/executor"
)

const mihomoDNSServerPrefix = "mihomo://"

type MihomoDNSClient struct {
	resolver *mihomoDNS.Resolver
	ipv6     bool
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
		resolver: resolvers.Resolver,
		ipv6:     ipv6,
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
			return cacheEntry.client, nil
		}
	}

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
			return cachedClient, nil
		}
	}

	client, err := NewMihomoDNSClientFromConfigBytes(configContent)
	if err != nil {
		return nil, err
	}

	mihomoDNSContentCache.Store(cacheKey, client)
	return client, nil
}

func (c *MihomoDNSClient) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	if c == nil || c.resolver == nil {
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
		addrs, err = c.resolver.LookupIP(ctx, domain)
	} else {
		addrs, err = c.resolver.LookupIPv4(ctx, domain)
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

// LookupByMihomoConfigFile resolves a domain with DNS settings from a mihomo config file.
func LookupByMihomoConfigFile(configPath string, domain string) ([]net.IP, error) {
	client, err := getCachedMihomoDNSClientFromConfigFile(configPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return client.LookupIP(ctx, domain)
}

// LookupByMihomoConfigBytes resolves a domain with DNS settings from in-memory mihomo config bytes.
func LookupByMihomoConfigBytes(configContent []byte, domain string) ([]net.IP, error) {
	client, err := getCachedMihomoDNSClientFromConfigBytes(configContent)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return client.LookupIP(ctx, domain)
}

// LookupByMihomoDNSServers resolves a domain by searching mihomo:// tokens in dns servers list.
// It returns matched=false when there is no mihomo:// token.
func LookupByMihomoDNSServers(domain string, queryServers []string) (ips []net.IP, matched bool, err error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, false, fmt.Errorf("empty domain")
	}

	var lastErr error
	for _, rawServer := range queryServers {
		server := strings.TrimSpace(rawServer)
		if server == "" {
			continue
		}
		configContent, tokenMatched, parseErr := parseMihomoDNSServerBase64(server)
		if !tokenMatched {
			continue
		}

		matched = true
		if parseErr != nil {
			lastErr = parseErr
			continue
		}

		ips, err = LookupByMihomoConfigBytes(configContent, domain)
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) > 0 {
			return ips, true, nil
		}
	}

	if !matched {
		return nil, false, nil
	}
	if lastErr != nil {
		return nil, true, lastErr
	}
	return nil, true, fmt.Errorf("mihomo dns has no ip for domain=%q", domain)
}
