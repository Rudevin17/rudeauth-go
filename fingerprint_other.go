//go:build !windows && !linux && !darwin

package rudeauth

// collectComponents has no hardware source defined on this platform, so it
// returns nothing and Authenticate refuses rather than sending a weak identity
// the server would have to accept. Add a member of the shared fingerprint spec
// for a platform before shipping to it.
func collectComponents() []string { return nil }
