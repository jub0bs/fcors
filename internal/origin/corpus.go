package origin

import (
	"strings"

	"github.com/jub0bs/fcors/internal/util"
)

// A Corpus represents a set of allowed (tuple) [Web origins].
// Internally, a corpus forms a tree in which
//
//   - edges stemming from the root are labeled by schemes of allowed origins,
//   - subsequent edges are each labeled
//     either with a DNS label of the domain of an allowed origin
//     (from the rightmost label to the leftmost label)
//     or with an IP address of an allowed origin,
//   - vertices represent a set of allowed ports for the corresponding
//     scheme-host combination.
//
// A trailing full stop in the origin's host results in an edge labeled with
// the empty string.
// An arbitrary DNS label is marked by a * label.
// One or more arbitrary DNS labels are marked by a ** label.
//
// Port numbers are offset by 1 for convenience.
// The absence of a port is marked by sentinel value 0.
// An arbitrary port is marked by sentinel value -1.
// For instance, consider the following origin patterns:
//
//	http://localhost:*
//	http://[::1]:9090
//	https://example.com:6060
//	https://example.com:8080
//	https://**.foobar.
//	https://*.example.com:7070
//
// Populating an empty corpus with them results in a tree that looks
// like this in memory:
//
//	x
//	│
//	├─── "http" ── x ── "localhost" ── x {-1}
//	│              │
//	│              └─── "::1" ── x {9091}
//	│
//	└─── "https" ── x ── "com" ── x ── "example" ── x {6061, 8081}
//	                │                               │
//	                │                               └─── "**" ── x {7071}
//	                │
//					└─── "" ── x ── "foobar" ── x ── "**" ── x {0}
//
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
type Corpus map[string]Vertex

var anyPortSingleton = util.NewSet(anyPortP1)

// Add adds spec to c.
func (c Corpus) Add(spec *Spec) {
	v, found := c[spec.Scheme]
	if !found {
		v = Vertex{edges: make(map[string]Vertex)}
		c[spec.Scheme] = v
	}
	edges := v.edges
	if spec.IsIP() { // the spec's host is an IP address
		v := edges[spec.Value]
		if done := v.add(spec.PortP1); done {
			return
		}
		edges[spec.Value] = v
		return
	}
	// the spec's host is a domain (not an IP address)
	for rest, found := spec.Value, true; found; edges = v.edges {
		var label string
		rest, label, found = cutRightmostLabel(rest)
		if !found || label == anyLabels || label == anyLabel {
			v = edges[label]
			if done := v.add(spec.PortP1); done {
				return
			}
			edges[label] = v
			return
		}
		v = edges[label]
		if v.edges == nil {
			v.edges = make(map[string]Vertex)
		}
		edges[label] = v
	}
}

// Contains returns true if c contains o, and false otherwise.
// The rules for port matching are aligned with [CSP's].
//
// [CSP's]: https://www.w3.org/TR/CSP3/#port-part-matches
func (c Corpus) Contains(o *Origin) bool {
	v, ok := c[o.Scheme]
	if !ok {
		return false
	}
	// the origin's scheme is present in the corpus
	edges := v.edges
	if o.Host.AssumeIP { // the origin's host is an IP address
		v, found := edges[o.Host.Value]
		if !found {
			return false
		}
		return v.contains(o.PortP1)
	}
	// the origin's host is a domain (not an IP address)
	for rest, found := o.Host.Value, true; found; edges = v.edges {
		// check whether arbitrarily deep subdomains are allowed here
		if v, ok := edges[anyLabels]; ok && v.contains(o.PortP1) {
			return true
		}
		var label string
		rest, label, found = cutRightmostLabel(rest)
		if !found { // label is the leftmost one in host
			// check whether an arbitrary label is allowed here
			if v, ok := edges[anyLabel]; ok && v.contains(o.PortP1) {
				return true
			}
		}
		v, ok = edges[label]
		if !ok {
			return false
		}
	}
	return v.contains(o.PortP1)
}

// A Vertex represents a vertex in the tree formed by a [Corpus].
type Vertex struct {
	edges   map[string]Vertex
	portP1s util.Set[int]
}

// size returns the number of distinct Web origins stemming from v.
// The bool result reports whether v contains a finite number of
// origins.
// Due to the recursive nature of the [Vertex] type,
// if v is one of its own descendants,
// calling this method causes a stack overflow:
//
//		v := Vertex{edges: make(map[string]Vertex)}
//		v.edges["https"] = v
//	    v.size() // overflows the stack!
//
// However, package [github.com/jub0bs/fcors/internal]
// is the only importer of the present package
// and never builds such a pathological Vertex value.
func (v *Vertex) size() (int, bool) {
	if v.portP1s.Contains(anyPortP1) {
		return 0, false
	}
	total := len(v.portP1s)
	for label, child := range v.edges {
		if label == anyLabel || label == anyLabels {
			return 0, false
		}
		size, finite := child.size()
		if !finite {
			return 0, false
		}
		total += size
	}
	return total, true
}

// cutRightmostLabel slices s around the last full stop,
// returning the text before and after that full stop.
// The found result reports whether a full stop appears in s.
// If no full stop appears in s, cutRightmostLabel returns
// the empty string, input string s, and false.
func cutRightmostLabel(s string) (before, label string, found bool) {
	if i := strings.LastIndexByte(s, fullStop); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return "", s, false
}

// add adds a port number to a Vertex
func (v *Vertex) add(portP1 int) (done bool) {
	switch {
	case v.portP1s.Contains(anyPortP1):
		// nothing more to do
		return true
	case portP1 == anyPortP1:
		// anyPortP1 subsumes any specific port
		v.portP1s = anyPortSingleton
	case v.portP1s == nil:
		v.portP1s = util.NewSet(portP1)
	default:
		v.portP1s.Add(portP1)
	}
	return false
}

// contains returns true if set contains at least of i
// and sentinel value anyPortP1, and false otherwise.
func (v *Vertex) contains(portP1 int) bool {
	return v.portP1s.Contains(portP1) || v.portP1s.Contains(anyPortP1)
}

// size returns the number of distinct Web origins contained in c.
// The bool result reports whether c contains a finite number of
// origins.
func (c Corpus) size() (int, bool) {
	var total int
	for _, v := range c {
		size, finite := v.size()
		if !finite {
			return 0, false
		}
		total += size
	}
	return total, true
}
