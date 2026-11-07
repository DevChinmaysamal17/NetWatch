package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var lastReply atomic.Int64

func getInterface(name string) (*net.Interface, net.IP, *net.IPNet) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Println("interface error:", err)
		os.Exit(1)
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return iface, ipn.IP.To4(), ipn
		}
	}
	fmt.Println("no IPv4 address found on", name)
	os.Exit(1)
	return nil, nil, nil
}

// hostsIn scans at most a /19 network and skips network and broadcast addresses.
func hostsIn(myIP net.IP, n *net.IPNet) []net.IP {
	ones, _ := n.Mask.Size()
	if ones < 19 {
		ones = 19
	}
	if ones >= 31 {
		return nil
	}
	mask := net.CIDRMask(ones, 32)
	base := binary.BigEndian.Uint32(myIP.Mask(mask))
	size := uint32(1) << (32 - ones)

	var hosts []net.IP
	for i := uint32(1); i < size-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+i)
		hosts = append(hosts, ip)
	}
	return hosts
}

// openHandle may require elevated privileges to capture and send packets.
func openHandle(name string) *pcap.Handle {
	handle, err := pcap.OpenLive(
		name,
		65536,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		fmt.Println("pcap error (try sudo):", err)
		os.Exit(1)
	}
	return handle
}

func listenForReplies(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	for pkt := range src.Packets() {
		layer := pkt.Layer(layers.LayerTypeARP)
		if layer == nil {
			continue
		}
		arp := layer.(*layers.ARP)
		if arp.Operation != layers.ARPReply {
			continue
		}

		ip := net.IP(arp.SourceProtAddress).String()
		mac := net.HardwareAddr(arp.SourceHwAddress).String()

		mu.Lock()
		devices[ip] = mac
		mu.Unlock()
	}
}

func scanNetwork(handle *pcap.Handle, iface *net.Interface, myIP net.IP, n *net.IPNet) {
	ones, _ := n.Mask.Size()
	fmt.Println("real mask: /", ones)
	hosts := hostsIn(myIP, n)
	fmt.Println("scanning", len(hosts), "addresses")

	for round := 0; round < 2; round++ {
		for i, target := range hosts {
			sendRequest(handle, iface, myIP, target)
			if i%16 == 15 {
				time.Sleep(time.Millisecond) // pace in bursts; per-packet 200µs sleeps are unreliable
			}
		}
		time.Sleep(150 * time.Millisecond) // let round 1 replies land before round 2
	}
	waitQuiet(300*time.Millisecond, 1500*time.Millisecond)
}

// waitQuiet returns once no reply has arrived for `quiet`, or after `max`.
func waitQuiet(quiet, max time.Duration) {
	start := time.Now()
	for {
		time.Sleep(50 * time.Millisecond)
		last := time.Unix(0, lastReply.Load())
		if last.Before(start) {
			last = start
		}
		if time.Since(last) >= quiet || time.Since(start) >= max {
			return
		}
	}
}

func sendRequest(handle *pcap.Handle, iface *net.Interface, myIP net.IP, target net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,
		Operation:       layers.ARPRequest,

		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(myIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(target),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}

func addSelf(iface *net.Interface, myIP net.IP) {
	mu.Lock()
	devices[myIP.String()] = iface.HardwareAddr.String()
	mu.Unlock()
}
