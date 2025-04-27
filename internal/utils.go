package internal

import (
	"fmt"
	"net"
	"strings"
)

func parseAsNetwork(value string) (*net.IPNet, error) {
	_, parsed_net, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value \"%v\" as network: %w", value, err)
	}
	return parsed_net, nil
}

func parseAsIp(value string) (*net.IPNet, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse value \"%v\" as IP", value)
	}
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(32, 32)
	} else {
		mask = net.CIDRMask(128, 128)
	}
	parsed_net := &net.IPNet{IP: ip, Mask: mask}
	return parsed_net, nil
}

func ParseIpNet(value string) (*net.IPNet, error) {
	if strings.Contains(value, "/") {
		return parseAsNetwork(value)
	} else {
		return parseAsIp(value)
	}
}
