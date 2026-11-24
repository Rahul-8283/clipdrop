//go:build !darwin && !windows

package doctor

// PlatformChecks returns platform-specific checks for non-Darwin and non-Windows OSes.
func PlatformChecks() []Check {
	return nil
}
