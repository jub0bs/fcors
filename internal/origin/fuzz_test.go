package origin

import (
	"strings"
	"testing"
)

func FuzzConsistencyBetweenParseSpecAndParse(f *testing.F) {
	for _, c := range parseSpecCases {
		f.Add(c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		spec, err := ParseSpec(pattern)
		if err != nil || spec.Kind.ArbitrarySubdomains() {
			t.Skip()
		}
		if _, ok := Parse(pattern); !ok {
			t.Errorf("pattern without wildcard %q fails to parse as an origin", pattern)
		}
	})
}

func FuzzParseSpec(f *testing.F) {
	for _, c := range parseSpecCases {
		f.Add(c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		spec, err := ParseSpec(pattern)
		if err != nil {
			t.Skip()
		}
		if strings.HasSuffix(pattern, ":*") {
			if spec.PortP1 != anyPortP1 {
				const tmpl = "pattern %q should but does not result" +
					" in a spec that allows arbitrary ports"
				t.Errorf(tmpl, pattern)
			}
			return
		}
		if strings.Contains(pattern, "*") != spec.Kind.ArbitrarySubdomains() {
			const tmpl = "pattern %q should but does not result" +
				" in a spec that allows arbitrary subdomains"
			t.Errorf(tmpl, pattern)
		}
	})
}

func FuzzCorpus(f *testing.F) {
	for _, c := range parseSpecCases {
		f.Add(c.input, c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input, c.input)
	}
	f.Fuzz(func(t *testing.T, pattern, orig string) {
		spec, err := ParseSpec(pattern)
		if err != nil {
			t.Skip()
		}
		corpus := make(Corpus)
		corpus.Add(spec)
		o, ok := Parse(orig)
		if !ok || !corpus.Contains(&o) {
			t.Skip()
		}
		const tmpl = "corpus built with pattern %q contains origin %q"
		if spec.Kind.ArbitrarySubdomains() {
			if !strings.HasPrefix(longestCommonSuffix(pattern, orig), ".") {
				t.Errorf(tmpl, pattern, orig)
			}
			return
		}
		if spec.PortP1 == anyPortP1 {
			if !strings.HasSuffix(longestCommonPrefix(pattern, orig), ":") {
				t.Errorf(tmpl, pattern, orig)
			}
			return
		}
		if orig != pattern {
			t.Errorf(tmpl, pattern, orig)
		}
	})
}

func longestCommonPrefix(a, b string) (out string) {
	for i, j := 0, 0; i < len(a) && j < len(b); i, j = i+1, j+1 {
		if a[i] != b[j] {
			out = a[:i+1]
			break
		}
	}
	return
}

func longestCommonSuffix(a, b string) (out string) {
	for i, j := len(a)-1, len(b)-1; 0 <= i && 0 <= j; i, j = i-1, j-1 {
		if a[i] != b[j] {
			out = a[i+1:]
			break
		}
	}
	return
}
