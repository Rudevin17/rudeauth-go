package rudeauth

import "os"

// fingerprintLabel is a human-readable machine name shown in the vendor's device
// list. It is not part of the identity, only a label.
func fingerprintLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// fingerprintCollect gathers tagged hardware components for the server's K-of-N
// device matching. Components that cannot be read are skipped, never
// substituted, because a placeholder shared across machines would make
// unrelated devices look identical.
//
// The per-OS component set (collectComponents) is the shared spec every RudeAuth
// SDK implements, so a device is recognised identically regardless of which SDK
// authenticated it. These values are client-supplied and therefore forgeable:
// device binding deters casual sharing, it is not a control against a motivated
// attacker.
func fingerprintCollect() []string {
	return collectComponents()
}
