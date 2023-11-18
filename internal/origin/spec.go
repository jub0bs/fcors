package origin

import (
	"net/netip"
	"strings"

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
	// marks one arbitrary label
	anyLabel = "*"
	// marks any positive number of arbitrary labels
	anyLabels = "**"
	// marks an arbitrary (possibly implicit) port number
	anyPort = "*"
	// sentinel value indicating that arbitrary port number are allowed
	anyPortP1 int = -1
)

// SpecKind represents the kind of a host pattern.
type SpecKind uint8

const (
	// domain without wildcards
	SpecKindDomain SpecKind = iota
	// non-loopback IP address
	SpecKindNonLoopbackIP
	// loopback IP address
	SpecKindLoopbackIP
	// domain with one arbitrary DNS label
	SpecKindDomainAnySub
	// domain with one or more arbitrary DNS labels
	SpecKindDomainAnySubOfAnyDepth
)

// ArbitrarySubdomains returns true if k is one of [SpecKindDomainAnySub]
// or [SpecKindDomainAnySubOfAnyDepth].
func (k SpecKind) ArbitrarySubdomains() bool {
	return k == SpecKindDomainAnySub || k == SpecKindDomainAnySubOfAnyDepth
}

// wildcardCharSeqLen returns the length of a wildcard character sequence.
func (k SpecKind) wildcardCharSeqLen() int {
	switch k {
	case SpecKindDomainAnySub:
		return len(anyLabel) + 1 // 1 for label separator
	case SpecKindDomainAnySubOfAnyDepth:
		return len(anyLabels) + 1 // 1 for label separator
	default:
		return 0
	}
}

type Spec struct {
	// Scheme is the origin spec's scheme.
	Scheme string
	// Scheme is the origin spec's host pattern.
	HostPattern
	// PortP1 is the origin spec's port number (if any) offset by 1.
	// For instance, a value of 8081 corresponds to port number 8080.
	// 0 is used as a sentinel value marking the absence of an explicit port.
	// -1 is used as a sentinel value to indicate that all ports are allowed.
	PortP1 int
}

func (s *Spec) IsDeemedInsecure() bool {
	return s.Scheme != schemeHTTPS &&
		s.Kind != SpecKindLoopbackIP &&
		s.hostOnly() != "localhost"
}

func (s *Spec) HostIsEffectiveTLD() (string, bool) {
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

func ParseSpec(s string) (*Spec, error) {
	if s == "*" {
		return nil, util.Errorf(`prohibited origin %q`, s)
	}
	if s == "null" {
		return nil, util.Errorf("prohibited origin %q", s)
	}
	full := s
	scheme, s, ok := scanHttpScheme(s)
	if !ok {
		const tmpl = "invalid or prohibited scheme: %q"
		return nil, util.Errorf(tmpl, full)
	}
	s, ok = consume(schemeHostSep, s)
	if !ok {
		const tmpl = "invalid or prohibited scheme: %q"
		return nil, util.Errorf(tmpl, full)
	}
	hostPattern, s, err := parseHostPattern(s, full)
	if err != nil {
		return nil, err
	}
	if hostPattern.IsIP() && scheme == schemeHTTPS {
		const tmpl = `scheme "https" incompatible with an IP address: %q`
		return nil, util.Errorf(tmpl, full)
	}
	port := -1 // assume no port
	if len(s) > 0 {
		s, ok = consume(string(hostPortSep), s)
		if !ok {
			return nil, util.InvalidOriginPatternErr(full)
		}
		port, s, ok = parsePortPattern(s)
		if !ok || s != "" {
			const tmpl = "invalid port pattern: %q"
			return nil, util.Errorf(tmpl, full)
		}
		if port+1 == anyPortP1 && hostPattern.Kind.ArbitrarySubdomains() {
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
	spec := Spec{
		HostPattern: *hostPattern,
		Scheme:      scheme,
		PortP1:      port + 1,
	}
	return &spec, nil
}

type HostPattern struct {
	// Value is the host pattern's raw value.
	Value string
	// Kind is the host pattern's kind.
	Kind SpecKind
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
	if pattern.Kind.ArbitrarySubdomains() {
		// At least two bytes (e.g. "a.") are required for the part
		// corresponding to the wildcard sequence in a valid origin,
		// hence the subtraction in the following expression.
		if len(host.Value) > maxHostLen-2 {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
		if host.AssumeIP {
			return nil, s, util.InvalidOriginPatternErr(full)
		}
	}
	// trim accordingly
	end := pattern.Kind.wildcardCharSeqLen() + len(host.Value)
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
			pattern.Kind = SpecKindLoopbackIP
		} else {
			pattern.Kind = SpecKindNonLoopbackIP
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
	return p.Kind == SpecKindLoopbackIP || p.Kind == SpecKindNonLoopbackIP
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
	switch hp.Kind {
	case SpecKindDomainAnySub:
		// *.example[.]com => example[.]com
		return hp.Value[len(anyLabel)+1:]
	case SpecKindDomainAnySubOfAnyDepth:
		// **.example[.]com => example[.]com
		return hp.Value[len(anyLabels)+1:]
	default:
		return hp.Value
	}
}

// parsePortPattern parses a port pattern. It returns the port number,
// the unconsumed part of the input string, and a bool that indicates
// success of failure.
func parsePortPattern(s string) (port int, rest string, ok bool) {
	if rest, ok = consume(anyPort, s); ok {
		return anyPortP1 - 1, rest, true
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

// peekKind checks for the presence of any leading wildcard character sequence
// in s and returns the associated spec kind.
// In the absence of any wildcard character sequence, it defaults to
// [SpecKindDomain].
func peekKind(s string) SpecKind {
	const (
		sgl = anyLabel + string(fullStop)
		dbl = anyLabels + string(fullStop)
	)
	switch {
	case strings.HasPrefix(s, sgl):
		return SpecKindDomainAnySub
	case strings.HasPrefix(s, dbl):
		return SpecKindDomainAnySubOfAnyDepth
	default:
		return SpecKindDomain
	}
}
