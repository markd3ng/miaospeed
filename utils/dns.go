package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	urllib "net/url"
	"strings"
	"sync"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils/structs/memutils"
	"github.com/airportr/miaospeed/utils/structs/obliviousmap"
)

var DnsCache *obliviousmap.ObliviousMap[*interfaces.IPStacks]

func DNSLookuper(addr string, queryServers []string) []net.IP {
	if len(queryServers) == 0 {
		result, _ := net.LookupIP(addr)
		return result
	}

	ipSets := map[string]net.IP{}
	for _, rawServer := range queryServers {
		server := strings.TrimSpace(rawServer)
		if server == "" {
			continue
		}
		// DoH query for HTTPS server
		lowerServer := strings.ToLower(server)
		if strings.HasPrefix(lowerServer, "https://") || strings.HasPrefix(lowerServer, "http://") {
			if ips := DohLookup(addr, server); len(ips) > 0 {
				for _, ip := range ips {
					ipSets[ip.String()] = ip
				}
			}

		} else {
			// nomal DNS query
			if _, _, err := net.SplitHostPort(server); err != nil {
				server = net.JoinHostPort(server, "53")
			}
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(3000),
					}
					return d.DialContext(ctx, network, server)
				},
			}
			addrs, _ := r.LookupIPAddr(context.Background(), addr)
			for _, ia := range addrs {
				ipSets[ia.IP.String()] = ia.IP
			}
		}
	}

	ips := make([]net.IP, len(ipSets))
	j := 0
	for _, ia := range ipSets {
		ips[j] = ia
		j += 1
	}

	return ips
}

func normalizeDoHEndpoint(dohServer string) (*urllib.URL, error) {
	dohServer = strings.TrimSpace(dohServer)
	if dohServer == "" {
		return nil, fmt.Errorf("empty DoH server")
	}

	endpoint, err := urllib.Parse(dohServer)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(endpoint.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("unsupported DoH scheme=%q", endpoint.Scheme)
	}
	if endpoint.Host == "" {
		return nil, fmt.Errorf("invalid DoH host")
	}

	endpoint.Scheme = scheme
	if endpoint.Path == "" || endpoint.Path == "/" {
		endpoint.Path = "/dns-query"
	}
	if endpoint.Path != "/" {
		endpoint.Path = strings.TrimSuffix(endpoint.Path, "/")
	}
	endpoint.Fragment = ""
	return endpoint, nil
}

// DohLookup Use DNS over HTTPS to query A and AAAA records
func DohLookup(domain, dohBaseURL string) []net.IP {
	endpoint, err := normalizeDoHEndpoint(dohBaseURL)
	if err != nil {
		DLogf("Invalid DoH endpoint | server=%q | err=%v\n", dohBaseURL, err)
		return nil
	}

	var wg sync.WaitGroup
	var ips []net.IP
	var mu sync.Mutex
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	queryDNS := func(qtype uint16) {
		defer wg.Done()

		query := dns.Msg{}
		query.SetQuestion(dns.Fqdn(domain), qtype)
		msg, err := query.Pack()
		if err != nil {
			DLogf("DNS over HTTPS request pack error | type=%d | err=%v\n", qtype, err)
			return
		}

		b64 := base64.RawURLEncoding.EncodeToString(msg)
		dohURL := *endpoint
		queryValues := dohURL.Query()
		queryValues.Set("dns", b64)
		dohURL.RawQuery = queryValues.Encode()

		req, err := http.NewRequest(http.MethodGet, dohURL.String(), nil)
		if err != nil {
			DLogf("Create request error | type=%d | err=%v\n", qtype, err)
			return
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			DLogf("DNS over HTTPS query error | type=%d | err=%v\n", qtype, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			DLogf("DNS over HTTPS bad status | type=%d | status=%d | body=%q\n", qtype, resp.StatusCode, strings.TrimSpace(string(bodyPreview)))
			return
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			DLogf("Read response body error | type=%d | err=%v\n", qtype, err)
			return
		}

		dnsResp := dns.Msg{}
		if err := dnsResp.Unpack(bodyBytes); err != nil {
			DLogf("DNS over HTTPS response unpack error | type=%d | err=%v\n", qtype, err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		for _, answer := range dnsResp.Answer {
			switch qtype {
			case dns.TypeA:
				if a, ok := answer.(*dns.A); ok {
					ips = append(ips, a.A)
				}
			case dns.TypeAAAA:
				if aaaa, ok := answer.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA)
				}
			}
		}
	}

	wg.Add(2)
	go queryDNS(dns.TypeA)    // A records
	go queryDNS(dns.TypeAAAA) // AAAA records

	wg.Wait()
	return ips
}

// queryServer = "8.8.8.8:53"
//func DNSLookuper(addr string, queryServers []string) []net.IP {
//	if len(queryServers) == 0 {
//		result, _ := net.LookupIP(addr)
//		return result
//	}
//
//	ipSets := map[string]net.IP{}
//	for _, server := range queryServers {
//		r := &net.Resolver{
//			PreferGo: true,
//			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
//				d := net.Dialer{
//					Timeout: time.Millisecond * time.Duration(3000),
//				}
//				return d.DialContext(ctx, network, server)
//			},
//		}
//		addrs, _ := r.LookupIPAddr(context.Background(), addr)
//		for _, ia := range addrs {
//			ipSets[ia.IP.String()] = ia.IP
//		}
//	}
//
//	ips := make([]net.IP, len(ipSets))
//	j := 0
//	for _, ia := range ipSets {
//		ips[j] = ia
//		j += 1
//	}
//
//	return ips
//}

func LookupIPv46(addr string, retry int, queryServers []string) *interfaces.IPStacks {
	token := fmt.Sprintf("%v|%v", addr, queryServers)
	if r, ok := DnsCache.Get(token); ok && r != nil {
		return r
	}

	var netips []net.IP
	for i := 0; i < retry && len(netips) == 0; i += 1 {
		netips = DNSLookuper(addr, queryServers)
	}
	DLogf("DNS Lookup | dns=%v result=%v", queryServers, netips)

	ipstacks := (&interfaces.IPStacks{}).Init()
	for _, ip := range netips {
		ipStr := ip.String()
		if !strings.Contains(ipStr, ":") {
			ipstacks.IPv4 = append(ipstacks.IPv4, ipStr)
		} else {
			ipstacks.IPv6 = append(ipstacks.IPv6, ipStr)
		}
	}

	if ipstacks.Count() > 0 {
		DnsCache.Set(token, ipstacks)
	} else {
		DWarnf("DNS Resolver | fail to resolve domain=%s", addr)
	}
	return ipstacks
}

func init() {
	memIPStacks := memutils.MemDriverMemory[*interfaces.IPStacks]{}
	memIPStacks.Init()
	DnsCache = obliviousmap.NewObliviousMap[*interfaces.IPStacks]("DnsCache/", time.Minute, true, &memIPStacks)
}
