package dns

import "fmt"

// Version is current version of miekg/dns
var Version = v{&Shadows, 1, 1, 35}
// Shadows is current version of AZ-X/dns a.k.a slim dns
var Shadows = v{nil, 1, 1, 38}

// v holds the version of this library.
type v struct {
	Shadows *v
	Major, Minor, Patch int
}

//dual version
func (v v) String() string {
	return fmt.Sprintf("%d.%d.%d-%d.%d.%d", v.Major, v.Minor, v.Patch, v.Shadows.Major, v.Shadows.Minor, v.Shadows.Patch)
}
