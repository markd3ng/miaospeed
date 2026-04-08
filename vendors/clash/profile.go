package clash

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/constant"
	vendorlog "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func init() {
	patch()
}

// patch is used to fix the logger exit function
func patch() {
	logger := vendorlog.StandardLogger()
	logger.ExitFunc = func(code int) {}
}
func parseProxy(proxyName, proxyPayload string) constant.Proxy {
	var payload map[string]any
	if err := yaml.Unmarshal([]byte(proxyPayload), &payload); err != nil {
		utils.DLogf("Vendor Parser | Parse clash profile yaml error, error=%v", err.Error())
		return nil
	}
	proxy, err := adapter.ParseProxy(payload)

	if err != nil {
		utils.DLogf("Vendor Parser | Parse clash profile error, error=%v", err.Error())
		return nil
	}

	return proxy
}

func extractFirstProxy(proxyName, proxyPayload string) constant.Proxy {
	proxy := parseProxy(proxyName, proxyPayload)
	if proxy == nil {
		return nil
	}
	if interfaces.Parse(proxy.Type().String()) != interfaces.ProxyInvalid {
		return proxy
	}

	return nil
}
