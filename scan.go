// scan.go
//
// Device discovery using ARP (Address Resolution Protocol).
//
// ARP in one sentence: a device asks the whole network "Who has IP x.x.x.x?
// Tell me your MAC address", and the owner of that IP answers.
// (OSI layer 2/3: it translates a layer-3 IP into a layer-2 MAC.)
//
// Flow: open the card -> listen for replies in the background ->
//
//	send a question for every address 1..254 -> collect the answers.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// getInterface finds the network card by name (e.g. "en0") and returns
// en0 name macOS gives the to network interface
// the card itself plus our own IPv4 address on it.
// We need our IP to know which subnet to scan (192.168.29.x) and to fill in
// the "who is asking" part of every ARP question.
func getInterface(name string) (*net.Interface, net.IP) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Println("interface error:", err)
		os.Exit(1) // can't continue without a network card
	}

	// A card can have several addresses (IPv4, IPv6...). Loop through them.
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		// Keep only IPv4 addresses. To4() returns nil for IPv6.
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return iface, ipn.IP.To4()
		}
	}

	fmt.Println("no IPv4 address found on", name)
	os.Exit(1)
	return nil, nil // never reached, Go just wants a return at the end
}

// openHandle opens the network card in "raw" mode so we can send and read
// packets directly. This is the part that needs sudo: raw access is
// restricted to root because it can see all traffic on the card.
func openHandle(name string) *pcap.Handle {
	handle, err := pcap.OpenLive(
		name,
		65536,             // max bytes to capture per packet (more than enough)
		true,              // promiscuous mode: also see packets not meant for us
		pcap.BlockForever, // wait for packets with no timeout
	)
	if err != nil {
		fmt.Println("pcap error (try sudo):", err)
		os.Exit(1)
	}
	return handle
}

// listenForReplies runs in the BACKGROUND (started with `go` in main).
// It watches every packet that arrives, keeps only ARP replies, and saves
// the sender's IP and MAC into the `devices` map.
func listenForReplies(handle *pcap.Handle) {
	// A "packet source" turns the raw bytes from the card into packets
	// we can inspect layer by layer.
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	// This loop runs for as long as the program is alive.
	for pkt := range src.Packets() {
		// Does this packet contain an ARP layer? If not, ignore it.
		layer := pkt.Layer(layers.LayerTypeARP)
		if layer == nil {
			continue
		}
		arp := layer.(*layers.ARP)

		// ARP packets are either questions (Request) or answers (Reply).
		// We only keep answers here.
		if arp.Operation != layers.ARPReply {
			continue
		}

		// In a reply, the "source" fields describe the device that answered:
		// its IP and its MAC. Convert the raw bytes to readable strings.
		ip := net.IP(arp.SourceProtAddress).String()
		mac := net.HardwareAddr(arp.SourceHwAddress).String()

		// Save it. Lock first, because main may be reading the map too.
		mu.Lock()
		devices[ip] = mac
		mu.Unlock()
	}
}

// scanNetwork asks every address on our /24 network (x.x.x.1 to x.x.x.254)
// "who has this IP?". Real devices answer, and listenForReplies catches
// those answers.
func scanNetwork(handle *pcap.Handle, iface *net.Interface, myIP net.IP) {
	// Two rounds, because a sleeping phone often misses the first question.
	for round := 0; round < 2; round++ {
		for i := 1; i <= 254; i++ {
			// Build the target by keeping our first 3 numbers and swapping
			// the last one. Example: 192.168.29.175 -> 192.168.29.<i>
			target := net.IPv4(myIP[0], myIP[1], myIP[2], byte(i)).To4()

			sendRequest(handle, iface, myIP, target)
		}
		time.Sleep(1 * time.Second) // pause before the next round
	}

	// Give slow devices time to answer before we move on.
	time.Sleep(2 * time.Second)
}

// sendRequest builds and sends ONE ARP question: "Who has <target>?".
//
// A packet is built in layers, like envelopes:
//
//	Ethernet (outer envelope: who it's from / to, on the local network)
//	  -> ARP (the actual question inside)
//
// This code is boilerplate: it is the same every time, so treat it as a
// black box that means "ask the network who owns `target`".
func sendRequest(handle *pcap.Handle, iface *net.Interface, myIP net.IP, target net.IP) {
	// Outer layer (OSI layer 2): the Ethernet frame.
	eth := layers.Ethernet{
		SrcMAC: iface.HardwareAddr, // from: our MAC
		// To: ff:ff:ff:ff:ff:ff is the BROADCAST address = "everyone on the
		// network". We don't know who owns the IP, so we ask all devices.
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP, // the payload inside is ARP
	}

	// Inner layer: the ARP question itself.
	arp := layers.ARP{
		AddrType:        layers.LinkTypeEthernet, // we're on Ethernet/Wi-Fi
		Protocol:        layers.EthernetTypeIPv4, // the addresses are IPv4
		HwAddressSize:   6,                       // a MAC is 6 bytes
		ProtAddressSize: 4,                       // an IPv4 address is 4 bytes
		Operation:       layers.ARPRequest,       // this is a question

		SourceHwAddress:   []byte(iface.HardwareAddr), // asker's MAC (us)
		SourceProtAddress: []byte(myIP),               // asker's IP (us)

		// The MAC we're looking for is unknown, that's the whole question,
		// so it's left as all zeros.
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0},

		DstProtAddress: []byte(target), // "who has THIS IP?"
	}

	// Turn the two layers into raw bytes and send them out of the card.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true, // fill in length fields automatically
		ComputeChecksums: true, // fill in checksums automatically
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}

// addSelf adds our own Mac to the device list by hand.
// A computer never answers its own ARP question, so without this our Mac
// would be missing from the table.
func addSelf(iface *net.Interface, myIP net.IP) {
	mu.Lock()
	devices[myIP.String()] = iface.HardwareAddr.String()
	mu.Unlock()
}
