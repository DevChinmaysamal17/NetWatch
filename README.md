# NetWatch

Home network monitor in Go: discovers devices on your LAN with ARP scanning. Building toward new-device alerts, port scan detection and automatic blocking.

> **Status:** early, work in progress. Device discovery and storage work today. Monitoring, detection and blocking are planned (see [Roadmap](#roadmap)).

## What it does today

- **ARP scan** of your local network using [gopacket](https://github.com/google/gopacket) (raw ARP requests, not the OS ARP cache).
- **Scan range from the netmask**: reads the interface's real subnet (e.g. `/24`, `/19`) instead of assuming a `/24`. Capped at `/19` (8,190 hosts) so a huge network doesn't flood the wifi.
- **Vendor lookup** from the MAC address using the IEEE OUI list (the first 3 bytes of a MAC identify the manufacturer).
- **Randomized MAC detection**: modern phones use private per-network MACs; these are labelled instead of shown as "unknown".
- **PostgreSQL storage**: known devices (upserted by MAC), a row per scan, and a per-scan sightings history.

Example output:

```
real mask: /24
scanning 254 addresses

NAME                              IP               MAC
--------------------------------------------------------------------
Example Router Corp               192.168.1.1      aa:bb:cc:00:00:01
Example IoT Vendor Ltd            192.168.1.20     aa:bb:dd:00:00:02
My-Laptop.local (this Mac)        192.168.1.35     02:00:00:00:00:03
randomized (private MAC)          192.168.1.42     da:00:00:00:00:04

devices found: 4
```

## How it works

1. Open the network card in raw mode (needs `sudo`) and listen for ARP replies in a background goroutine.
2. Send an ARP "who has <ip>?" request to every address in the subnet, in two rounds with short pauses so sleeping devices get a second chance.
3. Collect the replies (IP + MAC), add the local machine by hand (a host never answers its own ARP).
4. Look up each MAC's vendor, then save devices, the scan, and sightings to PostgreSQL.

## Requirements

- Go (see `go.mod` for the version)
- libpcap (preinstalled on macOS; `libpcap-dev` on Debian/Ubuntu)
- PostgreSQL
- `sudo` (raw packet access)
- The IEEE OUI list as `oui.csv` in the repo root

## Setup

```bash
# 1. Get the OUI vendor list
curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv

# 2. Create the database (connection string and tables: see db.go)
createdb netwatchdb

# 3. Build and run
make run
```

The network interface is currently hardcoded to `en0` (Wi-Fi on a Mac). Change it in `main.go` if yours is different.

## Project layout

| File | Purpose |
|---|---|
| `main.go` | Wires everything together: setup, scan, save, print |
| `scan.go` | ARP scanning: interface lookup, subnet range, send requests, collect replies |
| `oui.go` | Loads the IEEE OUI table and resolves MAC -> vendor |
| `names.go` | Picks the display name for a device |
| `db.go` | PostgreSQL connection and queries |

## Known limitations

- **Randomized MACs** have no manufacturer, so phones show as "randomized (private MAC)". Real names need DHCP hostname sniffing (planned) or manual labels.
- **A single scan is not the whole truth** on busy wifi: sleeping phones miss broadcasts and access points may drop them. The monitoring phase will track devices over time instead of trusting one scan.
- **Client isolation** on some networks hides devices from each other, so they never answer ARP.
- ARP only works on the local subnet, and NetWatch only sees what its own machine can see. It is not a full traffic monitor.
- macOS-first (`en0`); other platforms are untested.

## Roadmap

- [x] **Phase 1-2:** ARP scanner, PostgreSQL schema (devices / scans / sightings), upsert by MAC
- [x] **Phase 3 (mostly done):** netmask-based scan range, OUI vendor lookup. Remaining: key the in-memory map by MAC, measure recall against `nmap -sn`
- [ ] **Phase 4:** continuous scanning with event diffing (`device_events`: new, offline, ip_change), ignoring noise from randomized MACs
- [ ] ARP conflict detection (same IP claimed by different MACs, a sign of ARP spoofing)
- [ ] Device names via DHCP hostname sniffing, plus manual labels
- [ ] Port scan detection
- [ ] Automatic blocking of suspicious devices, without depending on router APIs
- [ ] Longer term: DNS-based detection (tunnelling, DGA, beaconing)

## Responsible use

Only run NetWatch on networks you own or have permission to scan.

## License

MIT License
