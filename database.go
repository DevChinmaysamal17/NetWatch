package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

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

func saveDevice(conn *pgx.Conn, mac string, ip string, hostname string) error {
	_, err := conn.Exec(
		context.Background(),
		`
		INSERT INTO devices (mac_address, ip_address, hostname)
		VALUES ($1, $2, $3)
		ON CONFLICT (mac_address)
		DO UPDATE SET
			ip_address = EXCLUDED.ip_address,
			hostname = EXCLUDED.hostname,
			last_seen = CURRENT_TIMESTAMP
		`,
		mac,
		ip,
		hostname,
	)

	return err
}
