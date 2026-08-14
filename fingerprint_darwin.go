//go:build darwin

package rudeauth

import (
	"os/exec"
	"strings"
)

// collectComponents is the macOS member of the shared fingerprint spec, read
// from IOPlatformExpertDevice via ioreg plus the hardware model.
func collectComponents() []string {
	var out []string
	push := func(tag, v string) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, tag+":"+v)
		}
	}
	push("platform-uuid", ioregValue("IOPlatformUUID"))
	push("serial", ioregValue("IOPlatformSerialNumber"))
	push("model", sysctl("hw.model"))
	return out
}

func ioregValue(key string) string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, `"`+key+`"`) {
			if i := strings.Index(line, "= "); i >= 0 {
				return strings.Trim(strings.TrimSpace(line[i+2:]), `"`)
			}
		}
	}
	return ""
}

func sysctl(name string) string {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
