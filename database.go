package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Both *pgx.Conn and pgx.Tx satisfy this.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type DeviceState struct {
	ID           int
	IP           string
	IsOnline     bool
	MissedScans  int
	IsRandomized bool
}

// Keyed by lowercase MAC ("aa:bb:cc:dd:ee:ff").
func loadDeviceStates(db DBTX) (map[string]DeviceState, error) {
	rows, err := db.Query(context.Background(), `
		SELECT id, mac_address::text, COALESCE(host(ip_address), ''),
		       is_online, missed_scans, is_randomized
		FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := make(map[string]DeviceState)
	for rows.Next() {
		var mac string
		var s DeviceState
		if err := rows.Scan(&s.ID, &mac, &s.IP, &s.IsOnline, &s.MissedScans, &s.IsRandomized); err != nil {
			return nil, err
		}
		states[mac] = s
	}
	return states, rows.Err()
}

func insertEvent(db DBTX, scanID, deviceID int, eventType, oldIP, newIP string) error {
	_, err := db.Exec(context.Background(), `
		INSERT INTO device_events (device_id, scan_id, event_type, old_ip, new_ip)
		VALUES ($1, $2, $3, NULLIF($4::text,'')::inet, NULLIF($5::text,'')::inet)`,
		deviceID, scanID, eventType, oldIP, newIP)
	return err
}

// Bumps the miss counter for every device not seen this scan, and flips
// is_online to false once it hits the threshold.
func recordMisses(db DBTX, seenIDs []int, threshold int) error {
	_, err := db.Exec(context.Background(), `
		UPDATE devices
		SET missed_scans = missed_scans + 1,
		    is_online    = CASE WHEN missed_scans + 1 >= $2 THEN false ELSE is_online END
		WHERE NOT (id = ANY($1))`,
		seenIDs, threshold)
	return err
}

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
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	return strings.ContainsRune("26ae", rune(strings.ToLower(mac)[1]))
}

// startScan inserts a new row into `scans` and returns its id.
// started_at fills itself in (DEFAULT now()), so we insert no columns.
func startScan(conn DBTX) (int, error) {
	var scanID int
	err := conn.QueryRow(
		context.Background(),
		`INSERT INTO scans DEFAULT VALUES RETURNING id`,
	).Scan(&scanID)
	return scanID, err
}

// saveDevice inserts a device, or updates it if its MAC is already known
// (an "upsert"). It returns the device's id so a sighting can point to it.
func saveDevice(conn DBTX, mac, ip, hostname string) (int, error) {
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
			is_online     = true,
			missed_scans  = 0,
			last_seen     = CURRENT_TIMESTAMP
		RETURNING id
		`,
		mac, ip, hostname, isRandomizedMAC(mac),
	).Scan(&deviceID)
	return deviceID, err
}

// saveSighting records that a device was seen in a given scan, at a given IP.
func saveSighting(conn DBTX, scanID, deviceID int, ip string) error {
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
func finishScan(conn DBTX, scanID, hostCount int) error {
	_, err := conn.Exec(
		context.Background(),
		`UPDATE scans SET finished_at = now(), host_count = $2 WHERE id = $1`,
		scanID, hostCount,
	)
	return err
}
