// Tables used:

// devices -> one row per unique MAC (current state, first/last seen)
// scans -> one row per run of the program
// sightings -> one row per (scan, device): "device X was seen in scan Y"
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// connectDB opens ONE connection to the local netwatchdb database.
// A single pgx.Conn is not safe to share between goroutines, which is fine
// because all DB writes happen in main's goroutine, after scanning.
func connectDB() (*pgx.Conn, error) {
	conn, err := pgx.Connect(
		context.Background(),
		"postgres://chinmaydattatraysamal@localhost:5432/netwatchdb",
	)
	if err != nil {
		return nil, err
	}
	fmt.Println("Connected to PostgreSQL")
	return conn, nil
}

// isRandomizedMAC reports whether a MAC is a "private"/randomized one.
// Phones rotate these on public WiFi, so one phone can look like several
// devices. The rule: if the 2nd hex character of the first byte is
// 2, 6, a or e, the "locally administered" bit is set (e.g. 1a:9e:..).
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	return strings.ContainsRune("26ae", rune(strings.ToLower(mac)[1]))
}

// startScan inserts a new row into `scans` and returns its id.
// started_at fills itself in (DEFAULT now()), so we insert no columns.
func startScan(conn *pgx.Conn) (int, error) {
	var scanID int
	err := conn.QueryRow(
		context.Background(),
		`INSERT INTO scans DEFAULT VALUES RETURNING id`,
	).Scan(&scanID)
	return scanID, err
}

// saveDevice inserts a device, or updates it if its MAC is already known
// (an "upsert"). It returns the device's id so a sighting can point to it.
//
//   - ON CONFLICT (mac_address): the MAC is the unique key, so a repeat
//     sighting updates the existing row instead of creating a duplicate.
//   - hostname: NULLIF turns "unknown" into NULL, then COALESCE keeps the
//     OLD hostname, so a scan that fails to resolve a name never overwrites
//     a good one with "unknown".
//   - RETURNING id: gives us the row's id for both new and updated rows.
func saveDevice(conn *pgx.Conn, mac, ip, hostname string) (int, error) {
	var deviceID int
	err := conn.QueryRow(
		context.Background(),
		`
		INSERT INTO devices (mac_address, ip_address, hostname, is_randomized)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (mac_address)
		DO UPDATE SET
			ip_address    = EXCLUDED.ip_address,
			hostname      = COALESCE(NULLIF(EXCLUDED.hostname, 'unknown'), devices.hostname),
			is_randomized = EXCLUDED.is_randomized,
			last_seen     = CURRENT_TIMESTAMP
		RETURNING id
		`,
		mac, ip, hostname, isRandomizedMAC(mac),
	).Scan(&deviceID)
	return deviceID, err
}

// saveSighting records that a device was seen in a given scan, at a given IP.
// The primary key is (scan_id, device_id), so ON CONFLICT DO NOTHING makes
// saving the same device twice in one scan harmless.
func saveSighting(conn *pgx.Conn, scanID, deviceID int, ip string) error {
	_, err := conn.Exec(
		context.Background(),
		`
		INSERT INTO sightings (scan_id, device_id, ip_address)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
		`,
		scanID, deviceID, ip,
	)
	return err
}

// finishScan stamps the scan row with its end time and how many devices
// were saved, so "how big was scan #N" is a simple lookup later.
func finishScan(conn *pgx.Conn, scanID, hostCount int) error {
	_, err := conn.Exec(
		context.Background(),
		`UPDATE scans SET finished_at = now(), host_count = $2 WHERE id = $1`,
		scanID, hostCount,
	)
	return err
}
