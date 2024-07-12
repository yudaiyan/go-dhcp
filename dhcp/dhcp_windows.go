package dhcp

import (
	"time"
)

func StartDhcp(ifname string) error {
	return StartDhcpTimeout(ifname, time.Hour*24*365)
}

func StartDhcpTimeout(ifname string, timeout time.Duration) error {
	return nil
}
