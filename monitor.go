package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var cycleCount int

func printHosts(hosts []Host) {
	sort.Slice(hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(hosts[i].IP)
		b, _ := netip.ParseAddr(hosts[j].IP)
		return a.Less(b)
	})
	fmt.Printf("\n%-34s %-16s %s\n", "NAME", "IP", "MAC")
	fmt.Println(strings.Repeat("-", 68))
	for _, h := range hosts {
		fmt.Printf("%-34s %-16s %s\n", h.Hostname, h.IP, h.MAC)
	}
	fmt.Printf("devices found: %d\n\n", len(hosts))
}

const offlineThreshold = 9

type Host struct {
	MAC, IP, Hostname string // MAC must be lowercased by the scanner
}

type Event struct {
	MAC        string
	Type       string // "new" | "offline" | "ip_change"
	OldIP      string
	NewIP      string
	Randomized bool
}

// Pure: no DB, no network. Easy to unit test.
func diff(prev map[string]DeviceState, current []Host, threshold int) []Event {
	var events []Event
	baseline := len(prev) == 0 // first run: don't alert on everything
	seen := make(map[string]bool, len(current))

	for _, h := range current {
		seen[h.MAC] = true
		old, known := prev[h.MAC]
		switch {
		case !known:
			if !baseline {
				events = append(events, Event{MAC: h.MAC, Type: "new", NewIP: h.IP,
					Randomized: isRandomizedMAC(h.MAC)})
			}
		case old.IP != "" && old.IP != h.IP:
			events = append(events, Event{MAC: h.MAC, Type: "ip_change",
				OldIP: old.IP, NewIP: h.IP, Randomized: old.IsRandomized})
		}
	}

	for mac, st := range prev {
		if !seen[mac] && st.IsOnline && st.MissedScans+1 >= threshold {
			events = append(events, Event{MAC: mac, Type: "offline",
				OldIP: st.IP, Randomized: st.IsRandomized})
		}
	}
	return events
}

func runCycle(conn *pgx.Conn, scan func() ([]Host, error)) error {
	ctx := context.Background()

	prev, err := loadDeviceStates(conn) // BEFORE any writes
	if err != nil {
		return err
	}

	hosts, err := scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("scan returned 0 hosts, skipping cycle")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) // no-op after a successful Commit

	scanID, err := startScan(tx)
	if err != nil {
		return err
	}

	ids := make(map[string]int)
	for mac, st := range prev {
		ids[mac] = st.ID
	}
	var seenIDs []int
	for _, h := range hosts {
		id, err := saveDevice(tx, h.MAC, h.IP, h.Hostname)
		if err != nil {
			return err
		}
		ids[h.MAC] = id
		seenIDs = append(seenIDs, id)
		if err := saveSighting(tx, scanID, id, h.IP); err != nil {
			return err
		}
	}
	events := diff(prev, hosts, offlineThreshold)

	for _, e := range events {
		if err := insertEvent(tx, scanID, ids[e.MAC], e.Type, e.OldIP, e.NewIP); err != nil {
			return err
		}
	}

	if err := recordMisses(tx, seenIDs, offlineThreshold); err != nil {
		return err
	}
	if err := finishScan(tx, scanID, len(hosts)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Print only after a successful commit, so the output never shows
	// events that got rolled back.
	printHosts(hosts)
	for _, e := range events {
		fmt.Printf("[%s] %s %s -> %s\n", e.Type, e.MAC, e.OldIP, e.NewIP)
	}
	fmt.Printf("%s cycle ok: %d hosts, %d events\n",
		time.Now().Format("15:04:05"), len(hosts), len(events))
	return nil
}

func monitor(conn *pgx.Conn, scan func() ([]Host, error), every time.Duration) {
	run := func() {
		if err := runCycle(conn, scan); err != nil {
			fmt.Println("cycle error:", err)
		}
	}
	run()
	for range time.NewTicker(every).C {
		run()
	}
}
