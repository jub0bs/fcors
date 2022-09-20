package origin

import (
	"strings"
)

const (
	schemeHostSep = "://"     // scheme-host separator
	hostPortSep   = ':'       // host-port separator
	fullStop      = '.'       // DNS-label separator
	maxUint16     = 1<<16 - 1 // maximum value for uint16 type
)

const (
	// maxHostLen is the maximum length of a host, which is dominated by
	// the maximum length of an (absolute) domain name (253);
	// see https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873.
	maxHostLen = 253
	// maxSchemeLen is the maximum length of the allowed schemes.
	maxSchemeLen = len(schemeHTTPS)
	// maxPortLen is the maximum length of a port's decimal representation.
	maxPortLen = len("65535")
	// maxHostPortLen is the maximum length of an origin's host-port part.
	maxHostPortLen = maxHostLen + 1 + maxPortLen // 1 for colon character
)

// Origin represents a (tuple) [Web origin].
//
// [Web origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin.
type Origin struct {
	// Scheme is the origin's scheme.
	Scheme string
	// Host is the origin's host.
	Host
	// PortP1 is the origin's port (if any) offset by 1 for convenience.
	// For example, a value of 9091 actually represents port 9090.
	// The zero value marks the absence of an explicit port.
	PortP1 int
}

var zeroOrigin Origin

// Parse parses a raw Web origin into an [Origin] structure.
// It is lenient insofar as it performs just enough validation for
// [Corpus.Contains] to know what to do with the resulting Origin value.
// In particular, the scheme and port of the resulting origin are guaranteed
// to be valid, but its host isn't.
func Parse(s string) (Origin, bool) {
	const maxOriginLen = maxSchemeLen + len(schemeHostSep) + maxHostPortLen
	if len(s) > maxOriginLen {
		return zeroOrigin, false
	}
	scheme, s, ok := scanHttpScheme(s)
	if !ok {
		return zeroOrigin, false
	}
	s, ok = consume(schemeHostSep, s)
	if !ok {
		return zeroOrigin, false
	}
	host, s, ok := fastParseHost(s)
	if !ok {
		return zeroOrigin, false
	}
	port := -1 // assume no port at first
	if len(s) > 0 {
		s, ok = consume(string(hostPortSep), s)
		if !ok {
			return zeroOrigin, false
		}
		port, s, ok = parsePort(s)
		if !ok || s != "" {
			return zeroOrigin, false
		}
	}
	o := Origin{
		Scheme: scheme,
		Host:   host,
		PortP1: port + 1,
	}
	return o, true
}

// Host represents a host, whether it be an IP address or a domain.
type Host struct {
	// Value is the origin's raw host.
	Value string
	// AssumeIP indicates whether the origin's host
	// should be treated as an IP address.
	AssumeIP bool
}

var zeroHost Host

// fastParseHost parses a raw host into an [Host] structure.
// It returns the parsed host, the unconsumed part of the input string,
// and a bool that indicates success of failure.
// fastParseHost is lenient insofar as the resulting host is
// not guaranteed to be valid.
func fastParseHost(s string) (Host, string, bool) {
	const (
		minIPv6HostLen = len("[::]")
		maxIPv6HostLen = len("[1111:1111:1111:1111:1111:1111:1111:1111]")
	)
	if len(s) >= minIPv6HostLen && s[0] == '[' { // looks like an IPv6 address
		end := strings.IndexByte(s, ']')
		if end < 0 { // unmatched left bracket
			return zeroHost, s, false
		}
		host := Host{
			Value:    s[1:end],
			AssumeIP: true,
		}
		return host, s[end+1:], true
	}
	// host can neither be empty nor start with a full stop
	if len(s) == 0 || s[0] == fullStop {
		return zeroHost, s, false
	}
	// host is either an IPv4 or a domain
	var (
		previousByteWasFullStop bool
		assumeIPv4              bool
		i                       int
	)
	// If the last non-empty label starts with a digit,
	// assume IPv4, since no TLD starts with a digit
	// (see https://www.iana.org/domains/root/db).
	for ; i < len(s); i++ {
		if s[i] == fullStop {
			if previousByteWasFullStop {
				// "empty" label, which can only occur at the end,
				// in case of an absolute domain name (e.g. "example.com.").
				// see https://www.rfc-editor.org/rfc/rfc1034.html#section-3.1
				host := Host{
					Value: s,
				}
				return host, "", false
			}
			previousByteWasFullStop = true
		} else if isDigit(s[i]) {
			if previousByteWasFullStop {
				assumeIPv4 = true
			}
			previousByteWasFullStop = false
		} else if isASCIILabelByte(s[i]) { // but is non-digit byte
			if previousByteWasFullStop {
				assumeIPv4 = false
			}
			previousByteWasFullStop = false
		} else {
			break
		}
	}
	host := Host{
		Value:    s[:i],
		AssumeIP: assumeIPv4,
	}
	return host, s[i:], true
}

// scanHttpScheme scans the more specific scheme among the allowed schemes,
// i.e. "https" and "http". It returns the scanned scheme, the unconsumed part
// of the input string, and a bool that indicates success of failure.
func scanHttpScheme(s string) (string, string, bool) {
	rest, ok := consume(schemeHTTPS, s)
	if ok {
		return schemeHTTPS, rest, true
	}
	rest, ok = consume(schemeHTTP, s)
	if ok {
		return schemeHTTP, rest, true
	}
	return "", s, false
}

// isASCIILabelByte returns true if b is an (ASCII) lowercase letter, digit,
// hyphen (0x2D), or underscore (0x5F).
func isASCIILabelByte(b byte) bool {
	return isLowerAlpha(b) || isDigit(b) || b == '-' || b == '_'
}

// parsePort parses a port number. It returns the port number, the unconsumed
// part of the input string, and a bool that indicates success of failure.
func parsePort(s string) (int, string, bool) {
	const base = 10
	var i int
	if len(s) == 0 || !isNonZeroDigit(s[0]) {
		return 0, s, false
	}
	port := intFromDigit(s[0])
	i++
	for end := min(len(s), maxPortLen); i < end; i++ {
		if !isDigit(s[i]) {
			break
		}
		port = base*port + intFromDigit(s[i])
	}
	if port < 0 || maxUint16 < port {
		return 0, s, false
	}
	return port, s[i:], true
}

// intFromDigit returns the numerical value of ASCII digit b.
// For instance, if b is '9', the result is 9.
func intFromDigit(b byte) int {
	return int(b) - '0'
}

// isDigit returns true if b is in the 0x30-0x39 ASCII range,
// and false otherwise.
func isDigit(b byte) bool {
	return '0' <= b && b <= '9'
}

// isNonZeroDigit returns true if b is in the 0x31-0x39 ASCII range,
// and false otherwise.
func isNonZeroDigit(b byte) bool {
	return '1' <= b && b <= '9'
}

// isLowerAlpha returns true if b is in the 0x61-0x7A ASCII range,
// and false otherwise.
func isLowerAlpha(b byte) bool {
	return 'a' <= b && b <= 'z'
}

// consume checks whether target is a prefix of s.
// If so, it consumes target in s, and returns the remainder of s and true.
// Otherwise, it returns s and false.
func consume(target, s string) (rest string, ok bool) {
	if !strings.HasPrefix(s, target) {
		return s, false
	}
	return s[len(target):], true
}

// min returns the smaller int among a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
