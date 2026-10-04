package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// devices maps IP -> MAC for every device that answers our scan.
// mu protects it: the listener goroutine writes while main reads.
var (
	devices = map[string]string{}
	mu      sync.Mutex
)

func main() {
	iface, myIP := getInterface("en0") // our network card + our IP
	handle := openHandle("en0")        // raw access to the network card
	defer handle.Close()

	go listenForReplies(handle)      // background: catch replies
	scanNetwork(handle, iface, myIP) // send "who has this IP?" to everyone
	addSelf(iface, myIP)             // our Mac never answers itself
	printTable(myIP)                 // show the results
}

// getInterface finds the network card (e.g. en0) and its IPv4 address.
func getInterface(name string) (*net.Interface, net.IP) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Println("interface error:", err)
		os.Exit(1)
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return iface, ipn.IP.To4()
		}
	}
	fmt.Println("no IPv4 address found on", name)
	os.Exit(1)
	return nil, nil
}

// openHandle opens the network card for raw packets. Needs sudo.
func openHandle(name string) *pcap.Handle {
	handle, err := pcap.OpenLive(name, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("pcap error (try sudo):", err)
		os.Exit(1)
	}
	return handle
}

// listenForReplies runs in the background and saves every ARP reply
// (a device saying "I'm this IP, and this is my MAC").
func listenForReplies(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		layer := pkt.Layer(layers.LayerTypeARP)
		if layer == nil {
			continue // not an ARP packet
		}
		arp := layer.(*layers.ARP)
		if arp.Operation != layers.ARPReply {
			continue // we only care about replies
		}

		ip := net.IP(arp.SourceProtAddress).String()
		mac := net.HardwareAddr(arp.SourceHwAddress).String()

		mu.Lock()
		devices[ip] = mac
		mu.Unlock()
	}
}

// scanNetwork asks every address 1-254 "who has this IP?", twice,
// because sleeping phones often miss the first request.
func scanNetwork(handle *pcap.Handle, iface *net.Interface, myIP net.IP) {
	for round := 0; round < 2; round++ {
		for i := 1; i <= 254; i++ {
			target := net.IPv4(myIP[0], myIP[1], myIP[2], byte(i)).To4()
			sendRequest(handle, iface, myIP, target)
		}
		time.Sleep(1 * time.Second)
	}
	time.Sleep(2 * time.Second) // wait for late replies
}

// sendRequest builds and sends ONE ARP request. Same boilerplate every time,
// so treat it as a black box: "ask the network who owns the target IP".
func sendRequest(handle *pcap.Handle, iface *net.Interface, myIP, target net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // broadcast: ask everyone
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr), // me (MAC)
		SourceProtAddress: []byte(myIP),               // me (IP)
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},   // unknown, that's the question
		DstProtAddress:    []byte(target),             // who has this IP?
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}

// addSelf adds our own Mac by hand, since it never replies to itself.
func addSelf(iface *net.Interface, myIP net.IP) {
	mu.Lock()
	devices[myIP.String()] = iface.HardwareAddr.String()
	mu.Unlock()
}

// lookupName asks DNS "what is the name of this IP?" (1 second max).
func lookupName(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "unknown"
	}
	return strings.TrimSuffix(names[0], ".")
}

// printTable sorts the devices by IP and prints name, IP and MAC.
func printTable(myIP net.IP) {
	// copy the IPs out of the map so we can sort them
	mu.Lock()
	ips := make([]string, 0, len(devices))
	for ip := range devices {
		ips = append(ips, ip)
	}
	mu.Unlock()

	// sort numerically, so .80 comes before .141
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(ips[i]).To4(), net.ParseIP(ips[j]).To4()) < 0
	})

	selfName, _ := os.Hostname()

	fmt.Printf("\n%-33s %-16s %s\n", "NAME", "IP", "MAC")
	fmt.Println(strings.Repeat("-", 58))
	for _, ip := range ips {
		name := lookupName(ip)
		if ip == myIP.String() {
			name = selfName + " (this Mac)"
		}
		fmt.Printf("%-33s %-16s %s\n", name, ip, devices[ip])
	}
	fmt.Println("\ndevices found:", len(ips))
}
