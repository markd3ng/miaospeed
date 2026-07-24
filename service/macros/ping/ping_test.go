package ping

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/metacubex/mihomo/constant"
)

type singleDialVendor struct {
	target string
}

func (v *singleDialVendor) Type() interfaces.VendorType {
	return interfaces.VendorInvalid
}

func (v *singleDialVendor) Status() interfaces.VendorStatus {
	return interfaces.VStatusOperational
}

func (v *singleDialVendor) Build(proxyName string, proxyInfo string) interfaces.Vendor {
	return v
}

func (v *singleDialVendor) DialTCP(ctx context.Context, url string, network interfaces.RequestOptionsNetwork) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, "tcp", v.target)
}

func (v *singleDialVendor) DialUDP(ctx context.Context, url string) (net.PacketConn, error) {
	return nil, nil
}

func (v *singleDialVendor) ProxyInfo() interfaces.ProxyInfo {
	return interfaces.ProxyInfo{}
}

func (v *singleDialVendor) Proxy() constant.Proxy {
	return nil
}

func TestPingViaNetCat_KeepAliveUnavailableFallsBackToFirstRTT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}

		time.Sleep(2 * time.Millisecond)
		_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
	}()

	vendor := &singleDialVendor{target: ln.Addr().String()}
	rtt, req, code, err := pingViaNetCat(context.Background(), vendor, "http://www.gstatic.com/generate_204")
	if err != nil {
		t.Fatalf("expected no error when fallback to first RTT, got: %v", err)
	}
	if rtt == 0 {
		t.Fatalf("expected non-zero RTT, got %d", rtt)
	}
	if req == 0 {
		t.Fatalf("expected non-zero request duration, got %d", req)
	}
	if code != 204 {
		t.Fatalf("expected status code 204, got %d", code)
	}

	<-done
}
