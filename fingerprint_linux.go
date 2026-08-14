//go:build linux

package rudeauth

import (
	"os"
	"strings"
)

// collectComponents is the Linux member of the shared fingerprint spec. Some DMI
// files require root and are simply skipped when unreadable; machine-id is
// world-readable, so a normal process still yields a usable identity.
func collectComponents() []string {
	var out []string
	push := func(tag, v string) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, tag+":"+v)
		}
	}
	push("machine-id", readFirstLine("/etc/machine-id"))
	push("product-uuid", readFirstLine("/sys/class/dmi/id/product_uuid"))
	push("board-serial", readFirstLine("/sys/class/dmi/id/board_serial"))
	push("product-serial", readFirstLine("/sys/class/dmi/id/product_serial"))
	push("cpu", cpuModel())
	return out
}

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}
