package clash

import (
	"context"
	"fmt"
	"github.com/airportr/miaospeed/utils"
	"github.com/metacubex/mihomo/component/resolver"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/metacubex/mihomo/constant"
)

type Clash struct {
	proxy      constant.Proxy
	proxyName  string
	proxyInfo  string
	dnsServers []string
}

func setupIPv6() {
	if utils.GCFG.EnableIPv6 {
		if resolver.DisableIPv6 {
			resolver.DisableIPv6 = false
		}
	}
}

func (c *Clash) Proxy() constant.Proxy {
	return c.proxy
}

func (c *Clash) Type() interfaces.VendorType {
	return interfaces.VendorClash
}

func (c *Clash) Status() interfaces.VendorStatus {
	if c == nil || c.proxy == nil {
		return interfaces.VStatusNotReady
	}

	return interfaces.VStatusOperational
}

func (c *Clash) Build(proxyName string, proxyInfo string) interfaces.Vendor {
	if c == nil {
		c = &Clash{}
	}
	c.proxyName = proxyName
	c.proxyInfo = proxyInfo
	c.rebuildProxy()
	return c
}

func (c *Clash) SetDNSServers(servers []string) {
	if c == nil {
		return
	}
	c.dnsServers = append([]string(nil), servers...)
	c.rebuildProxy()
}

func (c *Clash) rebuildProxy() {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.proxyInfo) == "" {
		c.proxy = nil
		return
	}
	proxy := extractFirstProxyWithDNS(c.proxyName, c.proxyInfo, c.dnsServers)
	if proxy != nil {
		c.proxy = proxy
	}
}

func pickResolvedIPForNetwork(ips []net.IP, network interfaces.RequestOptionsNetwork) (netip.Addr, bool) {
	if network == interfaces.ROptionsTCP6 {
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is6() {
				return addr, true
			}
		}
		return netip.Addr{}, false
	}

	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			return addr, true
		}
	}

	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is6() {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

func (c *Clash) applyMihomoDNSForDial(addr *constant.Metadata, network interfaces.RequestOptionsNetwork) {
	if c == nil || addr == nil || addr.Host == "" || len(c.dnsServers) == 0 {
		return
	}
	if _, err := netip.ParseAddr(addr.Host); err == nil {
		return
	}

	ips, matched, err := utils.LookupByMihomoDNSServers(addr.Host, c.dnsServers)
	if !matched {
		return
	}
	if err != nil {
		utils.DLogf("Mihomo DNS lookup failed | host=%q | proxy=%s | vendor=Clash | err=%v", addr.Host, c.proxy.Name(), err)
		return
	}
	resolvedIP, ok := pickResolvedIPForNetwork(ips, network)
	if !ok {
		utils.DLogf("Mihomo DNS resolved but no suitable IP | host=%q | network=%s | proxy=%s | vendor=Clash", addr.Host, network.String(), c.proxy.Name())
		return
	}

	addr.DstIP = resolvedIP
	addr.Host = ""
}

func (c *Clash) DialTCP(ctx context.Context, url string, network interfaces.RequestOptionsNetwork) (net.Conn, error) {
	if c == nil || c.proxy == nil {
		return nil, fmt.Errorf("should call Build() before run")
	}
	setupIPv6()
	//timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	//defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		addr, err := urlToMetadata(url, constant.TCP)
		if err != nil {
			ch <- result{nil, fmt.Errorf("cannot build tcp context: %v", err)}
		}
		c.applyMihomoDNSForDial(&addr, network)
		conn, err := c.proxy.DialContext(ctx, &addr)
		if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "no such host") {
			utils.DLogf("cannot dialTCP: %s | proxy=%s | vendor=Clash | err=%s", url, c.proxy.Name(), err.Error())
		}
		ch <- result{conn, err}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("dialTCP timeout: %w", ctx.Err())
	}
}

func (c *Clash) DialUDP(ctx context.Context, url string) (net.PacketConn, error) {
	if c == nil || c.proxy == nil {
		return nil, fmt.Errorf("should call Build() before run")
	}
	setupIPv6()
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type result struct {
		conn net.PacketConn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		addr, err := urlToMetadata(url, constant.UDP)
		if err != nil {
			ch <- result{nil, fmt.Errorf("cannot build udp context: %w", err)}
			return
		}

		conn, err := c.proxy.ListenPacketContext(timeoutCtx, &addr)
		if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "no such host") {
			utils.DLogf("cannot dialUDP: %s | proxy=%s | vendor=Clash | err=%s", url, c.proxy.Name(), err.Error())
		}
		ch <- result{conn, err}
	}()

	select {
	case res := <-ch:
		return res.conn, res.err
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("dialUDP timeout after 5 seconds: %w", timeoutCtx.Err())
	}
}
func (c *Clash) ProxyInfo() interfaces.ProxyInfo {
	if c == nil || c.proxy == nil {
		return interfaces.ProxyInfo{}
	}

	return interfaces.ProxyInfo{
		Name:    c.proxy.Name(),
		Address: c.proxy.Addr(),
		Type:    interfaces.Parse(c.proxy.Type().String()),
	}
}
