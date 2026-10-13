// names.go
//
// Picks a display name for a device: its manufacturer, looked up from the
// MAC address (see oui.go). Hostname discovery (mDNS) was removed.
package main

// getName returns the vendor for the device at this IP, or "unknown".
func getName(ip string) string {
	mu.Lock()
	mac := devices[ip]
	mu.Unlock()

	if mac == "" {
		return "unknown"
	}
	return Vendor(mac) // oui.go
}
