package main

import (
	"encoding/csv"
	"os"
	"strings"
)

var ouiTable = map[string]string{}

func loadOUI(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()

	if err != nil {
		return err
	}

	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue // skipping header line(first line) and faulty lines
		}
		ouiTable[strings.ToLower(row[1])] = row[2]

	}
	return nil
}

func Vendor(mac string) string {
	m := strings.ToLower(strings.ReplaceAll(mac, ":", ""))
	if len(m) < 6 {
		return "unknown"
	}
	// randomized MAC: 2nd hex digit of the first byte is 2, 6, a or e
	if strings.ContainsAny(string(m[1]), "26ae") {
		return "randomized (private MAC)"
	}
	if v, ok := ouiTable[m[:6]]; ok {
		return v
	}
	return "unknown"
}
