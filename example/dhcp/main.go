package main

import (
	"flag"
	"log"

	"github.com/go-errors/errors"
	"github.com/yudaiyan/go-dhcp/dhcp"
)

func main() {
	var ifname string
	flag.StringVar(&ifname, "ifname", "tap-dPeTE", "接口名")
	if err := dhcp.StartDhcp(ifname); err != nil {
		log.Fatalln(err.(*errors.Error).ErrorStack())
	}
	select {}
}
