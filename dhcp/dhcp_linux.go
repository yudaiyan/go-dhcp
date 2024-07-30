package dhcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-errors/errors"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/yudaiyan/go-netlink/netlink"
)

type dhcp struct {
	// 本地网卡名
	ifname string
	// ifname 的 localMac
	localMac net.HardwareAddr
	// 传递dhcp的负载
	ch chan *dhcpv4.DHCPv4
	// 匹配udp连接
	transactionID dhcpv4.TransactionID
	handle        *pcap.Handle
	ctx           context.Context
	// 整个过程超时时间
	timeout time.Duration
}

// 构建用于广播的eth、ipv4、udp层
func (s *dhcp) createBroadcastLayer() (*layers.Ethernet, *layers.IPv4, *layers.UDP) {
	// 构建以太网帧
	eth := &layers.Ethernet{
		SrcMAC:       s.localMac,            // 源 MAC 地址
		DstMAC:       nclient4.BroadcastMac, // 目标 MAC 地址
		EthernetType: layers.EthernetTypeIPv4,
	}
	// 构建 IP 层
	ipv4 := &layers.IPv4{
		SrcIP:    net.IPv4zero,  // 源 IP 地址
		DstIP:    net.IPv4bcast, // 目标 IP 地址
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
		Version:  4,
		TTL:      128,
	}

	// 构建 UDP 层
	udp := &layers.UDP{
		SrcPort: dhcpv4.ClientPort,
		DstPort: dhcpv4.ServerPort,
	}
	udp.SetNetworkLayerForChecksum(ipv4)
	return eth, ipv4, udp
}

// 发送广播包
func (s *dhcp) sendBroadcast(payload *dhcpv4.DHCPv4) error {

	eth, ipv4, udp := s.createBroadcastLayer()
	// 构建数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, opts,
		eth,
		ipv4,
		udp,
		gopacket.Payload(payload.ToBytes()),
	)
	// 发送数据包
	data := buffer.Bytes()
	return s.handle.WritePacketData(data)
}

// 打开网卡，用于监听和发送eth包
func (s *dhcp) openLive() error {
	// handle, err := pcap.OpenLive(s.ifname, 65535, true, pcap.BlockForever)
	handle, err := pcap.OpenLive(s.ifname, 65535, false, pcap.BlockForever)
	if err != nil {
		return errors.New(err)
	}
	s.handle = handle
	return nil
}

// 监听所有数据包，包括非eth。
// 不要使用 handle.SetBPFFilter 过滤包。
// 否则 packetSource.Packets() 无法获取到eof。
func (s *dhcp) listen(asyncCallback func(*gopacket.PacketSource)) error {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	go asyncCallback(packetSource)
	return nil
}

// 通过以下方式过滤出需要的包，而不是 s.handle.SetBPFFilter
func (s *dhcp) filter(packet gopacket.Packet) error {
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dhcp layers.DHCPv4
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ipv4,
		&udp,
		&dhcp,
	)
	foundLayerTypes := []gopacket.LayerType{}
	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	if err != nil {
		return errors.New(err)
	}
	if len(foundLayerTypes) < 4 {
		return errors.Errorf("not found all layers")
	}

	if udp.SrcPort != dhcpv4.ServerPort || udp.DstPort != dhcpv4.ClientPort {
		return errors.Errorf("udp的端口不匹配")
	}
	return nil
}

func (s *dhcp) dhclient() error {
	var cancel context.CancelFunc
	s.ctx, cancel = context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// 提前监听eth层，并使用异步回调
	err := s.listen(func(packetSource *gopacket.PacketSource) {
		defer func() {
			log.Println("closing")
			s.handle.Close()
			log.Println("closed")
		}()
		for {
			select {
			case <-s.ctx.Done():
				return
			case packet := <-packetSource.Packets():
				if err := s.filter(packet); err != nil {
					log.Println(err)
					continue
				}

				dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
				if dhcpLayer == nil {
					log.Println("非dhcp包")
					continue
				}
				m, err := dhcpv4.FromBytes(dhcpLayer.LayerContents())
				if err != nil {
					log.Printf("非dhcp包, err:%v", err)
					continue
				}
				if m.TransactionID != s.transactionID {
					log.Printf("unhandled transaction id: %v and %v", m.TransactionID, s.transactionID)
					continue
				}
				switch mt := m.MessageType(); mt {
				case dhcpv4.MessageTypeOffer, dhcpv4.MessageTypeAck:
					s.ch <- m
				default:
					log.Printf("unhandled message type: %v", mt)
					continue
				}
			}
		}
	})
	if err != nil {
		return errors.New(err)
	}

	// 发送 Discovery
	payload, err := dhcpv4.NewDiscoveryForInterface(s.ifname)
	s.transactionID = payload.TransactionID
	log.Println(s.transactionID)
	if err != nil {
		return errors.New(err)
	}
	err = s.sendBroadcast(payload)
	if err != nil {
		return errors.New(err)
	}

	// 等待 Offer
	var m *dhcpv4.DHCPv4
	select {
	case <-s.ctx.Done():
		return errors.Errorf("timeout")
	case m = <-s.ch:
		switch m.MessageType() {
		case dhcpv4.MessageTypeOffer:
			log.Printf("received message type: %v", m.MessageType())
		default:
			return errors.Errorf("unhandled message type: %v", m.MessageType())
		}
	}

	// 发送 Request
	payload, err = dhcpv4.NewRequestFromOffer(m)
	if err != nil {
		return errors.New(err)
	}
	err = s.sendBroadcast(payload)
	if err != nil {
		return errors.New(err)
	}

	// 等待 Ack
	select {
	case <-s.ctx.Done():
		return errors.Errorf("timeout")
	case m = <-s.ch:
		switch m.MessageType() {
		case dhcpv4.MessageTypeAck:
			log.Printf("received message type: %v", m.MessageType())
			ones, _ := m.SubnetMask().Size()
			cidrStr := fmt.Sprintf("%s/%d", m.YourIPAddr.String(), ones)
			// 设置网卡的ip、mask
			err := netlink.AddrAdd(s.ifname, cidrStr)
			if err != nil {
				return errors.New(err)
			}
			log.Printf("set %s to %s", s.ifname, cidrStr)
		default:
			return errors.Errorf("unhandled message type: %v", m.MessageType())
		}
	}
	return nil
}

func StartDhcp(ifname string) error {
	return StartDhcpTimeout(ifname, time.Hour*24*365)
}

func StartDhcpTimeout(ifname string, timeout time.Duration) error {
	client := dhcp{
		ifname:  ifname,
		ch:      make(chan *dhcpv4.DHCPv4),
		timeout: timeout,
	}
	mac, err := netlink.GetMac(ifname)
	if err != nil {
		return errors.New(err)
	}
	client.localMac = mac

	err = client.openLive()
	if err != nil {
		return errors.New(err)
	}

	return client.dhclient()
}
