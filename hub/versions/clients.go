package versions

import (
	"strconv"
	"strings"

	"github.com/blang/semver"

	"github.com/direct-connect/go-dc/types"
)

var aliases = map[string]string{
	"++":       "DC++",
	"StrgDC++": "StrongDC++",
}

var minVers = map[string]semver.Version{
	"DC++":        semver.MustParse("0.868.0"),
	"AirDC++":     semver.MustParse("3.53.0"),
	"AirDC++w":    semver.MustParse("2.7.0"),
	"EiskaltDC++": semver.MustParse("2.2.10"),
	"ncdc":        semver.MustParse("2.21.0"),
	"ApexDC++":    semver.MustParse("1.6.5"),
}

var latestVersionURL = map[string]string{
	"DC++":        "http://dcplusplus.sourceforge.net/",
	"AirDC++":     "https://airdcpp.net/download",
	"AirDC++w":    "https://airdcpp-web.github.io",
	"EiskaltDC++": "https://sourceforge.net/projects/eiskaltdcpp/files/latest/download",
	"ncdc":        "https://dev.yorhel.nl/ncdc",
	"ApexDC++":    "https://sourceforge.net/projects/apexdc/files/latest/download",
}

var unmaintained = map[string]struct{}{
	"StrongDC++": {},
	"gl++":       {},
	"DDD++":      {},
}

const (
	flylinkRevMin   = 504
	flylinkBuildMin = 21975
)

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	if v, ok := aliases[name]; ok {
		name = v
	}
	return name
}

func IsUnmaintained(soft types.Software) bool {
	soft.Name = normalizeName(soft.Name)
	_, ok := unmaintained[soft.Name]
	return ok
}

func IsSecure(soft types.Software) bool {
	soft.Name = normalizeName(soft.Name)
	// unmaintained are considered insecure
	if _, ok := unmaintained[soft.Name]; ok {
		return false
	}
	// special cases
	switch soft.Name {
	case "FlylinkDC++", "SkyLinkDC++":
		return isFlylinkSecure(soft.Version)
	}
	// semver or alike
	if min, ok := minVers[soft.Name]; ok {
		return minSemver(soft.Version, min)
	}
	return true // unknown
}

func minSemver(vers string, min semver.Version) bool {
	if strings.Count(vers, ".") < 2 {
		vers += ".0"
	}
	v, err := semver.Make(vers)
	if err != nil {
		return false
	}
	return v.GE(min)
}

func isFlylinkSecure(vers string) bool {
	if vers == "" || vers[0] != 'r' {
		// this should not happen
		return false
	}
	vers = vers[1:]
	vers = strings.ReplaceAll(vers, "-x64", "")
	sub := strings.SplitN(vers, "-", 3)
	rev, err := strconv.ParseUint(sub[0], 10, 16)
	if err != nil {
		return false
	} else if rev < flylinkRevMin {
		return false
	}
	switch len(sub) {
	case 1:
		return true
	case 2:
		build, err := strconv.ParseUint(sub[1], 10, 32)
		return err != nil || build < flylinkBuildMin
	default:
		return false
	}
}
