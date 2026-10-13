package main

import (
	"context"
	"log"
	"sync"
)

// Shared state used by every file in this package.
// The background listener (scan.go) WRITES to `devices`; main and the
// name lookups READ from it, so every access is wrapped in mu.
var (
	// devices maps IP -> MAC for every device that answered our ARP scan.
	devices = map[string]string{}

	// mdnsNames is no longer filled (mDNS removed). Kept only so names.go
	// still compiles; delete it once names.go no longer references it.
	mdnsNames = map[string]string{}

	// mu protects the maps above.
	mu sync.Mutex
)

func main() {
	// Load the manufacturer table (MAC prefix -> vendor). Without it every
	// device would silently show "unknown", so stop if it can't be read.
	if err := loadOUI("oui.csv"); err != nil {
		log.Fatal("loadOUI: ", err)
	}

	// DB setup: no point scanning if we can't reach PostgreSQL.
	conn, err := connectDB() // db.go
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())

	// One row in `scans` for this run; every device found is linked to it.
	scanID, err := startScan(conn) // db.go
	if err != nil {
		log.Fatal(err)
	}

	// 1. Find our network card (en0 = Wi-Fi on a Mac) and open it (needs sudo).
	iface, myIP := getInterface("en0") // scan.go
	handle := openHandle("en0")        // scan.go
	defer handle.Close()

	// 2. Listen for ARP replies in the background.
	go listenForReplies(handle) // scan.go

	// 3. Ask every address on the network "who are you?" (blocks until done).
	scanNetwork(handle, iface, myIP) // scan.go

	// 4. Our own Mac never replies to itself, so add it by hand.
	addSelf(iface, myIP) // scan.go

	// Copy the shared map under the lock, then release it so the slow DB
	// calls never block the background listener.
	mu.Lock()
	deviceSnapshot := make(map[string]string, len(devices))
	for ip, mac := range devices {
		deviceSnapshot[ip] = mac
	}
	mu.Unlock()

	count := 0

	for ip, mac := range deviceSnapshot {
		hostname := getName(ip) // names.go

		// No hostname found: fall back to the manufacturer from the MAC.
		if hostname == "unknown" {
			hostname = Vendor(mac) // oui.go
		}

		// Upsert into `devices`: new MAC creates a row, known MAC updates it.
		deviceID, err := saveDevice(conn, mac, ip, hostname)
		if err != nil {
			log.Println("saveDevice:", err)
			continue
		}

		// Record "seen in this scan, at this IP" in `sightings`.
		if err := saveSighting(conn, scanID, deviceID, ip); err != nil {
			log.Println("saveSighting:", err)
			continue
		}

		count++
	}

	// Close out the scan row with its end time and device count.
	if err := finishScan(conn, scanID, count); err != nil {
		log.Println("finishScan:", err)
	}

	// 6. Print the final table: name, IP, MAC.
	printTable(myIP) // names.go / scan.go
}
