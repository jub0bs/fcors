package origin

import (
	"math"
	"testing"
)

var parseCases = []struct {
	desc    string
	input   string
	want    Origin
	failure bool
}{
	{
		desc:  "domain without port",
		input: "https://example.com",
		want: Origin{
			Scheme: "https",
			Host: Host{
				Value: "example.com",
			},
		},
	}, {
		desc:    "unsupported scheme",
		input:   "foo://example.com:",
		failure: true,
	}, {
		desc:    "unsupported scheme starting with supported scheme",
		input:   "httpsfoo://example.com:",
		failure: true,
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[example]:90",
		want: Origin{
			Scheme: "http",
			Host: Host{
				Value:    "example",
				AssumeIP: true,
			},
			PortP1: 90 + 1,
		},
	}, {
		desc:    "unmatched left bracket",
		input:   "http://[::1:90",
		failure: true,
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[::1:]",
		want: Origin{
			Scheme: "http",
			Host: Host{
				Value:    "::1:",
				AssumeIP: true,
			},
		},
	}, {
		desc:  "brackets containing non-IPv6 chars",
		input: "http://[::]",
		want: Origin{
			Scheme: "http",
			Host: Host{
				Value:    "::",
				AssumeIP: true,
			},
		},
	}, {
		desc:  "valid compressed IPv6",
		input: "http://[::1]:90",
		want: Origin{
			Scheme: "http",
			Host: Host{
				Value:    "::1",
				AssumeIP: true,
			},
			PortP1: 90 + 1,
		},
	}, {
		desc:    "valid compressed IPv6 followed by a trailing full stop",
		input:   "http://[::1].:90",
		failure: true,
	}, {
		desc:    "domain with colon but without port",
		input:   "https://example.com:",
		failure: true,
	}, {
		desc:    "domain with a leading full stop",
		input:   "https://.example.com",
		failure: true,
	}, {
		desc:    "domain with invalid char after host",
		input:   "https://example.com^8080",
		failure: true,
	}, {
		desc:    "domain followed by character other than colon",
		input:   "https://example.com?",
		failure: true,
	}, {
		desc:    "domain with colon but with non-numeric port",
		input:   "https://example.com:abcd",
		failure: true,
	}, {
		desc:    "domain with colon but with non-numeric port starting with digits",
		input:   "https://example.com:123ab",
		failure: true,
	}, {
		desc:  "domain port",
		input: "https://example.com:6060",
		want: Origin{
			Scheme: "https",
			Host:   Host{Value: "example.com"},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "ipv4 port",
		input: "http://127.0.0.1:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "127.0.0.1", AssumeIP: true},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "ipv4 with trailing full stop",
		input: "http://127.0.0.1.",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "127.0.0.1.", AssumeIP: true},
		},
	}, {
		desc:  "malformed ipv4 with one too many octets",
		input: "http://127.0.0.1.1",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "127.0.0.1.1", AssumeIP: true},
		},
	}, {
		desc:  "ipv4 with overflowing octet",
		input: "http://256.0.0.1",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "256.0.0.1", AssumeIP: true},
		},
	}, {
		desc:  "ipv4 with trailing full stop and port",
		input: "http://127.0.0.1.:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "127.0.0.1.", AssumeIP: true},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "invalid TLD",
		input: "http://foo.bar.255:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "foo.bar.255", AssumeIP: true},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "longer invalid TLD",
		input: "http://foo.bar.baz.012345678901234567890123456789:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "foo.bar.baz.012345678901234567890123456789", AssumeIP: true},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "valid domain with all-numeric label in the middle",
		input: "http://foo.bar.baz.012345678901234567890123456789.ab:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "foo.bar.baz.012345678901234567890123456789.ab"},
			PortP1: 6060 + 1,
		},
	}, {
		desc:  "ipv6 with port",
		input: "http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:6060",
		want: Origin{
			Scheme: "http",
			Host:   Host{Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", AssumeIP: true},
			PortP1: 6060 + 1,
		},
	}, {
		desc: "deep_subdomain",
		input: "http://foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred." +
			"example.com:6060",
		failure: true,
	},
}

func TestParse(t *testing.T) {
	for _, c := range parseCases {
		f := func(t *testing.T) {
			o, ok := Parse(c.input)
			if ok == c.failure || ok && o != c.want {
				t.Errorf("%q: want %v, %t; got %v, %t", c.input, c.want, !c.failure, o, ok)
			}
		}
		t.Run(c.desc, f)
	}
}

func BenchmarkParse(b *testing.B) {
	for _, c := range parseCases {
		f := func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Parse(c.input)
			}
		}
		b.Run(c.desc, f)
	}
}

func TestMaxUint16(t *testing.T) {
	if maxUint16 != math.MaxUint16 {
		const tmpl = "incorrect maxUint16 value: got %d; want %d"
		t.Errorf(tmpl, maxUint16, math.MaxUint16)
	}
}
