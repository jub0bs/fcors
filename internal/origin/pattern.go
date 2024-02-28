package origin

import (
	"net/netip"
	"strings"

	"github.com/jub0bs/fcors/internal/radix"
	"github.com/jub0bs/fcors/internal/util"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	portHTTP    = 80
	portHTTPS   = 443
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

const (
	// marks one or more period-separated arbitrary DNS labels
	subdomainWildcard = "*"
	// marks an arbitrary (possibly implicit) port number
	portWildcard = "*"
	// sentinel value indicating that arbitrary port numbers are allowed
	anyPort int = radix.WildcardElem
)

// PatternKind represents the kind of a host pattern.
type PatternKind uint8

const (
	// domain
	PatternKindDomain PatternKind = iota
	// non-loopback IP address
	PatternKindNonLoopbackIP
	// loopback IP address
	PatternKindLoopbackIP
	// arbitrary subdomains of depth one or more
	PatternKindSubdomains
)

type Pattern struct {
	// Scheme is the origin pattern's scheme.
	Scheme string
	// Scheme is the origin pattern's host pattern.
	HostPattern
	// Port is the origin pattern's port number (if any).
	// 0 is used as a sentinel value marking the absence of an explicit port.
	// -1 is used as a sentinel value to indicate that all ports are allowed.
	Port int
}

func (s *Pattern) IsDeemedInsecure() bool {
	return s.Scheme != schemeHTTPS &&
		s.Kind != PatternKindLoopbackIP &&
		s.hostOnly() != "localhost"
}

func (s *Pattern) HostIsEffectiveTLD() (string, bool) {
	host := s.HostPattern.hostOnly()
	// For cases like of a Web origin that ends with a full stop,
	// we need to trim the latter for this check.
	host = strings.TrimSuffix(host, string(fullStop))
	// We ignore the second (boolean) result because
	// it's false for some listed eTLDs (e.g. github.io)
	etld, _ := publicsuffix.PublicSuffix(host)
	if etld == host {
		return host, true
	}
	return "", false
}

func ParsePattern(s string) (*Pattern, error) {
	if s == "*" {
		return nil, util.Errorf(`prohibited origin %q`, s)
	}
	if s == "null" {
		return nil, util.Errorf("prohibited origin %q", s)
	}
	full := s
	scheme, s, ok := scanHttpScheme(s)
	if !ok {
		return nil, util.InvalidOriginPatternErr(full)
	}
	s, ok = consume(schemeHostSep, s)
	if !ok {
		return nil, util.InvalidOriginPatternErr(full)
	}
	hostPattern, s, err := parseHostPattern(s, full)
	if err != nil {
		return nil, err
	}
	if hostPattern.IsIP() && scheme == schemeHTTPS {
		const tmpl = `scheme "https" incompatible with an IP address: %q`
		return nil, util.Errorf(tmpl, full)
	}
	var port int // assume no port
	if len(s) > 0 {
		s, ok = consume(string(hostPortSep), s)
		if !ok {
			return nil, util.InvalidOriginPatternErr(full)
		}
		port, s, ok = parsePortPattern(s)
		if !ok || s != "" {
			return nil, util.InvalidOriginPatternErr(full)
		}
		if port == anyPort && hostPattern.Kind == PatternKindSubdomains {
			const tmpl = "specifying both arbitrary subdomains " +
				"and arbitrary ports is prohibited: %q"
			return nil, util.Errorf(tmpl, full)
		}
		if isDefaultPortForScheme(scheme, port) {
			const tmpl = "default port %d for %q scheme " +
				"needlessly specified: %q"
			return nil, util.Errorf(tmpl, port, scheme, full)
		}
	}
	pattern := Pattern{
		HostPattern: *hostPattern,
		Scheme:      scheme,
		Port:        port,
	}
	return &pattern, nil
}

type HostPattern struct {
	// Value is the host pattern's raw value.
	Value string
	// Kind is the host pattern's kind.
	Kind PatternKind
}

// parseHostPattern parses a raw host pattern into an [HostPattern] structure.
// It returns the parsed host pattern, the unconsumed part of the input string,
// and an error.
func parseHostPattern(s, full string) (*HostPattern, string, error) {
	pattern := HostPattern{
		Value: s, // temporary value, to be trimmed later
		Kind:  peekKind(s),
	}
	host, s, ok := fastParseHost(pattern.hostOnly())
	if !ok {
		return nil, s, util.InvalidOriginPatternErr(full)
	}
	if pattern.Kind == PatternKindSubdomains {
		// At least two bytes (e.g. "a.") are required for the part
		// corresponding to the wildcard character sequence in a valid origin,
		// hence the subtraction in the following expression.
		if len(host.Value) > maxHostLen-2 {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
		if host.AssumeIP {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
	}
	// trim accordingly
	end := len(host.Value)
	if pattern.Kind == PatternKindSubdomains {
		end += len(subdomainWildcard) + 1 // 1 for label separator
	}
	pattern.Value = pattern.Value[:end]
	if host.AssumeIP {
		ip, err := netip.ParseAddr(host.Value)
		if err != nil {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
		if ip.Zone() != "" {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
		if ip.Is4In6() {
			const tmpl = "prohibited IPv4-mapped IPv6 address: %q"
			return nil, s, util.Errorf(tmpl, full)
		}
		var ipStr = ip.String()
		if ipStr != host.Value {
			const tmpl = "IP address in uncompressed form: %q"
			return nil, s, util.Errorf(tmpl, full)
		}

		if ip.IsLoopback() {
			pattern.Kind = PatternKindLoopbackIP
		} else {
			pattern.Kind = PatternKindNonLoopbackIP
		}
		pattern.Value = ipStr
		return &pattern, s, nil
	}
	_, err := profile.ToASCII(host.Value)
	if err != nil {
		const tmpl = "host not in ASCII form: %q"
		return nil, s, util.Errorf(tmpl, full)
	}
	return &pattern, s, nil
}

func (p *HostPattern) IsIP() bool {
	return p.Kind == PatternKindLoopbackIP || p.Kind == PatternKindNonLoopbackIP
}

var profile = idna.New(
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// hostOnly returns strictly the host part of the pattern,
// without any leading wildcard character sequence.
func (hp *HostPattern) hostOnly() string {
	if hp.Kind == PatternKindSubdomains {
		// *.example[.]com => example[.]com
		return hp.Value[len(subdomainWildcard)+1:]
	}
	return hp.Value
}

// parsePortPattern parses a port pattern. It returns the port number,
// the unconsumed part of the input string, and a bool that indicates
// success of failure.
func parsePortPattern(s string) (port int, rest string, ok bool) {
	if rest, ok = consume(portWildcard, s); ok {
		return anyPort, rest, true
	}
	return parsePort(s)
}

// isDefaultPortForScheme returns true for the following combinations
//
//   - https, 443
//   - http, 80
//
// and false otherwise.
func isDefaultPortForScheme(scheme string, port int) bool {
	return port == portHTTP && scheme == schemeHTTP ||
		port == portHTTPS && scheme == schemeHTTPS
}

// peekKind checks for the presence of a wildcard character sequence
// in s and returns the associated pattern kind.
// In the absence of any wildcard character sequence, it defaults to
// [PatternKindDomain].
func peekKind(s string) PatternKind {
	const wildcardSeq = subdomainWildcard + string(fullStop)
	if strings.HasPrefix(s, wildcardSeq) {
		return PatternKindSubdomains
	}
	return PatternKindDomain
}
