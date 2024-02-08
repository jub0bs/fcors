package origin

import (
	"fmt"
	"strings"
	"testing"
)

func buildCorpus(patterns ...string) (Corpus, error) {
	c := make(Corpus)
	for _, pattern := range patterns {
		spec, err := ParseSpec(pattern)
		if err != nil {
			return c, err
		}
		c.Add(spec)
	}
	return c, nil
}

var corpusTestCases = []struct {
	patterns []string
	accept   []string
	reject   []string
}{
	{
		patterns: []string{},
		reject: []string{
			"https://foo.example.com",
			"http://foo.example.com",
		},
	}, {
		patterns: []string{"https://foo.example.com"},
		accept:   []string{"https://foo.example.com"},
		reject: []string{
			"http://foo.example.com",
			"https://foo.example.com:9090",
			"https://foo.example.com.",
			"https://example.com",
			"https://fooexample.com",
			"https://foo.example.computer",
			"https://qux.baz.bar.foo.example.com",
		},
	}, {
		patterns: []string{"http://169.254.169.254"},
		accept:   []string{"http://169.254.169.254"},
		reject: []string{
			"http://169.254.169.254:6060",
			"http://168.254.169.254",
			"http://[2001:db8:aaaa:1111::100]",
		},
	}, {
		patterns: []string{"http://[2001:db8:aaaa:1111::100]"},
		accept:   []string{"http://[2001:db8:aaaa:1111::100]"},
		reject: []string{
			"http://[2001:db8:aaaa:1111::100]:6060",
			"http://[2001:db8:aaaa:1111::111]",
			"http://168.254.169.254",
		},
	}, {
		patterns: []string{"https://foo.example.com."},
		accept:   []string{"https://foo.example.com."},
		reject: []string{
			"http://foo.example.com.",
			"https://foo.example.com.:9090",
			"https://foo.example.com",
			"https://example.com.",
			"https://fooexample.com.",
			"https://foo.example.comp.uter",
			"https://qux.baz.bar.foo.example.com.",
		},
	}, {
		patterns: []string{"https://*.foo.example.com"},
		accept: []string{
			"https://bar.foo.example.com",
			"https://baz.bar.foo.example.com",
		},
		reject: []string{
			"https://foo.example.com",
			"https://foo.example.com:6060",
			"http://foo.example.com",
			"https://quux.example.com",
		},
	}, {
		patterns: []string{"https://*.foo.example.com"},
		accept: []string{
			"https://bar.foo.example.com",
			"https://baz.bar.foo.example.com",
		},
		reject: []string{
			"https://foo.example.com",
			"https://foo.example.com:6060",
			"http://foo.example.com",
			"https://quux.example.com",
		},
	}, {
		patterns: []string{
			"https://foo.example.com",
			"https://*.foo.example.com",
		},
		accept: []string{
			"https://foo.example.com",
			"https://bar.foo.example.com",
			"https://baz.bar.foo.example.com",
		},
		reject: []string{
			"http://foo.example.com",
			"http://bar.foo.example.com",
			"https://foo.example.com:6060",
			"https://bar.foo.example.com:6060",
			"https://qux.example.com",
		},
	}, {
		patterns: []string{
			"https://*.foo.example.com",
			"https://foo.example.com",
		},
		accept: []string{
			"https://foo.example.com",
			"https://bar.foo.example.com",
			"https://baz.bar.foo.example.com",
		},
		reject: []string{
			"http://foo.example.com",
			"http://bar.foo.example.com",
			"https://foo.example.com:6060",
			"https://bar.foo.example.com:6060",
			"https://qux.example.com",
		},
	}, {
		patterns: []string{"https://foo.example.com:9090"},
		accept:   []string{"https://foo.example.com:9090"},
		reject: []string{
			"http://foo.example.com:9090",
			"https://foo.example.com:8080",
			"https://foo.example.com",
			"https://qux.example.com:9090",
			"https://bar.foo.example.com:9090",
			"https://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{
			"https://foo.example.com:8080",
			"https://foo.example.com:9090",
		},
		accept: []string{
			"https://foo.example.com:8080",
			"https://foo.example.com:9090",
		},
		reject: []string{
			"https://foo.example.com:7070",
			"http://foo.example.com:9090",
			"http://foo.example.com:8080",
			"https://foo.example.com",
			"https://qux.example.com:9090",
			"https://bar.foo.example.com:9090",
			"https://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{"https://foo.example.com:*"},
		accept: []string{
			"https://foo.example.com",
			"https://foo.example.com:8080",
			"https://foo.example.com:9090",
		},
		reject: []string{
			"https://qux.example.com:9090",
			"https://bar.foo.example.com:9090",
			"https://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{
			"https://foo.example.com:9090",
			"https://foo.example.com:*",
		},
		accept: []string{
			"https://foo.example.com",
			"https://foo.example.com:8080",
			"https://foo.example.com:9090",
		},
		reject: []string{
			"https://qux.example.com:9090",
			"https://bar.foo.example.com:9090",
			"https://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{
			"https://foo.example.com:*",
			"https://foo.example.com:9090",
		},
		accept: []string{
			"https://foo.example.com",
			"https://foo.example.com:8080",
			"https://foo.example.com:9090",
		},
		reject: []string{
			"https://qux.example.com:9090",
			"https://bar.foo.example.com:9090",
			"https://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{"http://169.254.169.254:*"},
		accept: []string{
			"http://169.254.169.254",
			"http://169.254.169.254:8080",
			"http://169.254.169.254:9090",
		},
		reject: []string{
			"http://169.254.169.255",
			"http://169.254.169.255:8080",
			"http://169.254.169.255:9090",
		},
	}, {
		patterns: []string{
			"http://169.254.169.254:*",
			"http://169.254.169.254:9090",
		},
		accept: []string{
			"http://169.254.169.254",
			"http://169.254.169.254:8080",
			"http://169.254.169.254:9090",
		},
		reject: []string{
			"http://169.254.169.255",
			"http://169.254.169.255:8080",
			"http://169.254.169.255:9090",
		},
	}, {
		patterns: []string{
			"http://169.254.169.254:9090",
			"http://169.254.169.254:*",
		},
		accept: []string{
			"http://169.254.169.254",
			"http://169.254.169.254:8080",
			"http://169.254.169.254:9090",
		},
		reject: []string{
			"http://169.254.169.255",
			"http://169.254.169.255:8080",
			"http://169.254.169.255:9090",
		},
	}, {
		patterns: []string{
			"https://*.foo.example.com",
			"https://foo.bar.baz.qux.quux.foo.bar.baz.qux.quux.foo.example.com",
			"https://quux.foo.example.com",
			"https://qux.quux.foo.example.com",
		},
		accept: []string{
			"https://bar.foo.example.com",
			"https://foo.bar.baz.qux.quux.foo.bar.baz.qux.quux.foo.example.com",
			"https://quux.foo.example.com",
			"https://qux.quux.foo.example.com",
			"https://baz.bar.foo.example.com",
		},
		reject: []string{
			"http://bar.foo.example.com",
			"https://bar.foo.example.com:9090",
			"https://foo.example.com",
			"https://quux.example.com",
			"http://foo.example.com",
			"http://quux.example.com",
			"http://baz.bar.foo.example.com",
			"http://foo.example.com:9090",
			"http://quux.example.com:9090",
			"http://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{
			"https://*.foo.example.com",
			"https://foo.bar.baz.qux.quux.foo.bar.baz.qux.quux.foo.example.com",
			"https://quux.foo.example.com",
			"https://qux.quux.foo.example.com",
		},
		accept: []string{
			"https://bar.foo.example.com",
			"https://baz.bar.foo.example.com",
			"https://foo.bar.baz.qux.quux.foo.bar.baz.qux.quux.foo.example.com",
			"https://quux.foo.example.com",
			"https://qux.quux.foo.example.com",
		},
		reject: []string{
			"http://bar.foo.example.com",
			"https://bar.foo.example.com:9090",
			"https://foo.example.com",
			"https://quux.example.com",
			"http://baz.bar.foo.example.com",
			"http://foo.example.com",
			"http://quux.example.com",
			"http://foo.example.com:9090",
			"http://quux.example.com:9090",
			"http://baz.bar.foo.example.com:9090",
		},
	}, {
		patterns: []string{
			"https://a" + strings.Repeat(".a", maxHostLen/2),
		},
		accept: []string{
			"https://a" + strings.Repeat(".a", maxHostLen/2),
		},
		reject: []string{
			"https://b" + strings.Repeat(".a", maxHostLen/2),
		},
	},
}

func TestCorpus(t *testing.T) {
	for _, c := range corpusTestCases {
		corpus, err := buildCorpus(c.patterns...)
		if err != nil {
			t.Errorf("failure to build corpus: %v", err)
			return
		}
		for _, rawOrigin := range c.accept {
			f := func(t *testing.T) {
				o, ok := Parse(rawOrigin)
				if !ok {
					t.Errorf("failure to parse origin %q", rawOrigin)
					return
				}
				got := corpus.Contains(&o)
				if !got {
					t.Errorf("origin should be accepted, but is rejected")
				}
			}
			const tmpl = "corpus made up of %s versus origin %s"
			desc := fmt.Sprintf(tmpl, strings.Join(c.patterns, " "), rawOrigin)
			t.Run(desc, f)
		}
		for _, rawOrigin := range c.reject {
			f := func(t *testing.T) {
				o, ok := Parse(rawOrigin)
				if !ok {
					t.Errorf("failure to parse origin %q", rawOrigin)
					return
				}
				got := corpus.Contains(&o)
				if got {
					t.Error("origin should be rejected, but is accepted")
				}
			}
			const tmpl = "corpus made up of %s versus origin %s"
			desc := fmt.Sprintf(tmpl, strings.Join(c.patterns, " "), rawOrigin)
			t.Run(desc, f)
		}
	}
}

func BenchmarkCorpus(b *testing.B) {
	for _, c := range corpusTestCases {
		corpus, err := buildCorpus(c.patterns...)
		if err != nil {
			b.Errorf("failure to build corpus: %v", err)
			return
		}
		f := func(rawOrigin string) func(b *testing.B) {
			return func(b *testing.B) {
				o, ok := Parse(rawOrigin)
				if !ok {
					b.Errorf("failure to parse origin %q", rawOrigin)
					return
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					corpus.Contains(&o)
				}
			}
		}
		const tmpl = "corpus made up of %s versus origin %s"
		for _, rawOrigin := range c.accept {
			desc := fmt.Sprintf(tmpl, strings.Join(c.patterns, " "), rawOrigin)
			b.Run(desc, f(rawOrigin))
		}
		for _, rawOrigin := range c.reject {
			desc := fmt.Sprintf(tmpl, strings.Join(c.patterns, " "), rawOrigin)
			b.Run(desc, f(rawOrigin))
		}
	}
}
