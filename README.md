# NetWatch

Home network monitor in Go: discovers devices on your LAN with ARP scanning and watches them continuously. Detects new devices, devices going offline and IP changes. Building toward alerts, port scan detection and automatic blocking.

> **Status:** work in progress. Discovery, storage and continuous monitoring with event detection work today. Alerts, detection and blocking are planned (see [Roadmap](#roadmap)).

## What it does today

- **Continuous monitoring**: rescans the network every 5 seconds and diffs each scan against the last known state.
- **Change events** stored in `device_events`:
  - `new`: a MAC never seen before joined the network
  - `offline`: a device missed several scans in a row
  - `ip_change`: a known MAC now has a different IP
- **Debounced offline detection**: one missed scan is not "offline" (phones in wifi power-save drop ARP replies). A device is marked offline after 9 consecutive misses (about 45 seconds at the default interval).
- **Fast ARP scan** using [gopacket](https://github.com/google/gopacket) (raw ARP requests, not the OS ARP cache). Two send rounds, then an adaptive wait that returns as soon as replies stop arriving instead of sleeping a fixed time. A scan takes about a second.
- **Scan range from the netmask**: reads the interface's real subnet (e.g. `/24`, `/19`) instead of assuming a `/24`. Capped at `/19` (8,190 hosts) so a huge network doesn't flood the wifi.
- **Vendor lookup** from the MAC address using the IEEE OUI list (the first 3 bytes of a MAC identify the manufacturer).
- **Randomized MAC detection**: modern phones use private per-network MACs; these are labelled instead of shown as "unknown".
- **PostgreSQL storage**: known devices with live state (online, last IP, missed scans), a row per scan, a per-scan sightings history, and the event log.
- **Safe cycles**: each scan cycle runs in one database transaction, so a failure midway never leaves half-written state. A scan that fails or finds zero hosts is skipped instead of marking everything offline.

Example output:

```
real mask: /24
scanning 254 addresses

NAME                               IP               MAC
--------------------------------------------------------------------
Example Router Corp                192.168.1.1      aa:bb:cc:00:00:01
Example IoT Vendor Ltd             192.168.1.20     aa:bb:dd:00:00:02
My-Laptop.local (this Mac)         192.168.1.35     02:00:00:00:00:03
randomized (private MAC)           192.168.1.42     da:00:00:00:00:04
devices found: 4

[offline] da:00:00:00:00:04 192.168.1.42 ->
18:42:46 cycle ok: 3 hosts, 1 events
```

## How it works

Each cycle (`runCycle` in `monitor.go`):

1. Load the previous state of every known device from PostgreSQL (before any writes, so changes can be detected).
2. Scan: send ARP requests to every address in the subnet in two rounds, collect replies (IP + MAC) in a background listener goroutine, and add the local machine by hand (a host never answers its own ARP).
3. Skip the cycle if the scan failed or found nothing.
4. In one transaction: upsert devices (marks them online and resets their miss counter), record sightings, run the diff, store the resulting events, increment miss counters for devices that did not answer, and close the scan row.
5. Commit, then print the device table and any events.

The diff itself (`diff` in `monitor.go`) is a pure function with no database or network access, which keeps it easy to test. The first run against an empty database is treated as a baseline and does not fire `new` events.

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

# 2. Create the database
createdb netwatchdb
```

3. Create the tables (run in `psql netwatchdb`):

```sql
CREATE TABLE devices (
  id            bigserial PRIMARY KEY,
  mac_address   macaddr NOT NULL UNIQUE,
  ip_address    inet,
  hostname      text,
  first_seen    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_randomized boolean NOT NULL DEFAULT false,
  is_online     boolean NOT NULL DEFAULT true,
  missed_scans  int     NOT NULL DEFAULT 0
);

CREATE TABLE scans (
  id          serial PRIMARY KEY,
  started_at  timestamptz DEFAULT now(),
  finished_at timestamptz,
  host_count  integer
);

CREATE TABLE sightings (
  scan_id    integer NOT NULL REFERENCES scans(id),
  device_id  integer NOT NULL REFERENCES devices(id),
  ip_address inet,
  PRIMARY KEY (scan_id, device_id)
);

CREATE TABLE device_events (
  id         bigserial PRIMARY KEY,
  device_id  bigint  NOT NULL REFERENCES devices(id),
  scan_id    integer REFERENCES scans(id),
  event_type text    NOT NULL CHECK (event_type IN ('new','offline','ip_change')),
  old_ip     inet,
  new_ip     inet,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_device  ON device_events (device_id, created_at DESC);
CREATE INDEX idx_events_created ON device_events (created_at DESC);
```

The connection string is in `database.go`. Then build and run:

```bash
make run
```

Stop it with Ctrl+C.

The network interface is currently hardcoded to `en0` (Wi-Fi on a Mac). Change it in `main.go` if yours is different. The scan interval and offline threshold are `5*time.Second` in `main.go` and `offlineThreshold` in `monitor.go`.

## Project layout

| File | Purpose |
|---|---|
| `main.go` | Setup, opens the network card once, wraps the scan and starts the monitor loop |
| `monitor.go` | The monitoring loop, per-cycle transaction, and the `diff` function that produces events |
| `scan.go` | ARP scanning: interface lookup, subnet range, send requests, collect replies |
| `oui.go` | Loads the IEEE OUI table and resolves MAC -> vendor |
| `names.go` | Picks the display name for a device |
| `database.go` | PostgreSQL connection and queries |

## Known limitations

- **Randomized MACs** have no manufacturer, so phones show as "randomized (private MAC)". A phone that rotates its MAC will appear as a new device. Real names need DHCP hostname sniffing (planned) or manual labels.
- **Offline detection is a tradeoff.** About 45 seconds at the defaults. Lowering it risks false `offline` events from phones that ignore ARP while their wifi sleeps.
- **No `online` event yet**: a device coming back after being offline updates its state but does not fire an event.
- **Sightings grow fast**: one row per device per scan (every 5 seconds). Fine at home, but there is no retention policy yet.
- **Client isolation** on some networks hides devices from each other, so they never answer ARP.
- ARP only works on the local subnet, and NetWatch only sees what its own machine can see. It is not a full traffic monitor.
- Ctrl+C stops the program immediately with no graceful shutdown.
- macOS-first (`en0`); other platforms are untested.

## Roadmap

- [x] **Phase 1-2:** ARP scanner, PostgreSQL schema (devices / scans / sightings), upsert by MAC
- [x] **Phase 3:** netmask-based scan range, OUI vendor lookup, scan accuracy checked against `nmap -sn`
- [x] **Phase 4:** continuous scanning with event diffing (`device_events`: new, offline, ip_change), debounced offline detection, faster adaptive scan
- [ ] Alerts for new and offline devices (Discord or Telegram webhook)
- [ ] Unit tests for `diff`
- [ ] Ignore or downgrade noise from randomized MACs
- [ ] Targeted re-probe of devices that miss a scan (faster offline detection without false alarms)
- [ ] Passive ARP sniffing (detect new devices instantly, without waiting for a scan)
- [ ] ARP conflict detection (same IP claimed by different MACs, a sign of ARP spoofing)
- [ ] Device names via DHCP hostname sniffing, plus manual labels
- [ ] Port scan detection
- [ ] Automatic blocking of suspicious devices, without depending on router APIs
- [ ] Longer term: DNS-based detection (tunnelling, DGA, beaconing)

## Responsible use

Only run NetWatch on networks you own or have permission to scan.

## License

MIT License
