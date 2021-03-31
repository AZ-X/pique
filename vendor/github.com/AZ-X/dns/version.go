package dns

import "fmt"

// Version is current release version sync with miekg/dns
var Version = v{&shadows, 1, 1, 38}
// Shadows is current version of AZ-X/dns a.k.a slim dns
var shadows = v{nil, 1, 1, 39}

// v holds the version of this library.
type v struct {
	shadows *v
	Major, Minor, Patch int
}

//dual version
func (v v) String() string {
	return fmt.Sprintf("%d.%d.%d-%d.%d.%d", v.Major, v.Minor, v.Patch, v.shadows.Major, v.shadows.Minor, v.shadows.Patch)
}
