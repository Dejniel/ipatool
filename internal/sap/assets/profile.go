package assets

import "howett.net/plist"

// Validate checks all size and digest pins before native profile entry points
// are used. A caller-supplied bundle must obey the same contract as Load.
func Validate(bundle Bundle) error { return validate(bundle) }

// SystemVersion describes the pinned image, never the analyst's host system.
func SystemVersion() ([]byte, error) {
	return plist.Marshal(map[string]string{"ProductVersion": macOSVersion, "ProductBuildVersion": macOSBuild, "ProductName": "macOS"}, plist.XMLFormat)
}
