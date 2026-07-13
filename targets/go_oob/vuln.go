package vuln

// Index returns the byte at a fixed offset in b. It never checks the length, so any input
// shorter than 101 bytes panics with an index out of range. A caller that feeds
// attacker-controlled bytes turns that panic into a denial of service.
func Index(b []byte) byte {
	return b[100]
}
