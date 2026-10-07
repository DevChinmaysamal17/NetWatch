// main.go
//
// NetWatch entry point. This file only holds the shared data and the
// high-level steps. The real work lives in the other files:
//
//	scan.go    -> finds devices using ARP
//	names.go   -> finds device names (mDNS + reverse DNS)
//	display.go -> prints the final table
package main

import (
	"context"
	"log"
	"sync"
)

// Shared state used by every file in this package.
//
// Two goroutines touch these maps at the same time:
//   - the background listener (scan.go) WRITES to `devices`
//   - main and the name lookups READ from them
//
// Two goroutines on one map at once can crash Go, so every access is
// wrapped in mu.Lock() / mu.Unlock() (a mutex = "one at a time" lock).
var (
	// devices maps IP -> MAC for every device that answered our ARP scan.
	// Example: "192.168.29.80" -> "48:7e:48:c1:3f:ef"
	devices = map[string]string{}

	// mdnsNames maps IP -> hostname learned through mDNS.
	// Example: "192.168.29.175" -> "Chinmays-Laptop.local"
	mdnsNames = map[string]string{}

	// mu protects both maps above.
	mu sync.Mutex
)

func main() {

	conn, err := connectDB()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())
	// 1. Setup: find our network card (en0 = Wi-Fi on a Mac) and our own IP,
	//    then open the card for raw packet access (needs sudo).
	iface, myIP := getInterface("en0") // from scan.go
	handle := openHandle("en0")        // from scan.go
	defer handle.Close()               // close the card when main() ends

	// 2. Start listening for ARP replies in the BACKGROUND (goroutine).
	go listenForReplies(handle) //from scan.go
	// 3. Ask every address on the network "who are you?" (blocks until done).
	scanNetwork(handle, iface, myIP) //from scan.go

	// 4. Our own Mac never replies to itself, so add it by hand.
	addSelf(iface, myIP) //from scan.go

	// 5. Ask devices to announce their names through mDNS.
	discoverMDNS() //from names.go

	mu.Lock()

	deviceSnapshot := make(map[string]string, len(devices))

	for ip, mac := range devices {
		deviceSnapshot[ip] = mac
	}

	mu.Unlock()

	for ip, mac := range deviceSnapshot {
		hostname := getName(ip)

		err := saveDevice(conn, mac, ip, hostname)
		if err != nil {
			log.Println("database error:", err)
		}
	}

	// 6. Print the final table: name, IP, MAC.
	printTable(myIP)
}
