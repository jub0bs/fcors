package fcors_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
)

type middleware struct {
	name string
	cors fcors.Middleware
	reqs []request
}

type request struct {
	name    string
	method  string
	headers http.Header
}

func requestHeadersAllowedByDefaultInRsCORS() fcors.Option {
	return fcors.WithRequestHeaders(
		"Accept",
		"Content-Type",
		"X-Requested-With",
	)
}

func identity[T any](t T) T { return t }

func BenchmarkMiddleware(b *testing.B) {
	var middlewares []middleware
	mw := middleware{
		name: "without CORS config",
		cors: identity[http.Handler],
	}
	mw.reqs = []request{
		{
			name:   "CORS preflight request from some origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from some origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
			},
		},
	}
	middlewares = append(middlewares, mw)

	var (
		cors fcors.Middleware
		err  error
		f    func(b *testing.B)
	)

	mw = middleware{name: "allow arbitrary origin"}
	f = func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccess(
				fcors.FromAnyOrigin(),
				requestHeadersAllowedByDefaultInRsCORS(),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from some origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from some origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
			},
		},
	}
	middlewares = append(middlewares, mw)

	mw = middleware{name: "allow one origin"}
	f = func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccess(
				fcors.FromOrigins("https://example.com"),
				requestHeadersAllowedByDefaultInRsCORS(),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
			},
		}, {
			name:   "CORS preflight request from disallowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://attacker.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from disallowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://attacker.com"},
			},
		},
	}
	middlewares = append(middlewares, mw)

	mw = middleware{name: "allow multiple origins"}
	f = func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccess(
				fcors.FromOrigins(
					"https://*.example.com",
					"https://*.google.com",
					"https://*.twitter.com",
					"https://*.stackoverflow.com",
					"https://*.reddit.com",
					"https://*.quora.com",
					"https://*.example.co.uk",
					"https://*.google.co.uk",
					"https://*.twitter.co.uk",
					"https://*.stackoverflow.co.uk",
					"https://*.reddit.co.uk",
					"https://*.quora.co.uk",
					"https://*.example.com.au",
					"https://*.google.com.au",
					"https://*.twitter.com.au",
					"https://*.stackoverflow.com.au",
					"https://*.reddit.com.au",
					"https://*.quora.com.au",
					"https://*.example.fr",
					"https://*.google.fr",
					"https://*.twitter.fr",
					"https://*.stackoverflow.fr",
					"https://*.reddit.fr",
					"https://*.quora.fr",
				),
				requestHeadersAllowedByDefaultInRsCORS(),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://foo.quora.fr"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://foo.quora.fr"},
			},
		}, {
			name:   "CORS preflight request from disallowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://attacker.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from disallowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://attacker.com"},
			},
		}, {
			name:   "CORS preflight request from abnormally long origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {abnormallyLongOrigin},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from abnormally long origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {abnormallyLongOrigin},
			},
		},
	}
	middlewares = append(middlewares, mw)

	mw = middleware{name: "allow one pathological origin"}
	origin := "https://a" + strings.Repeat(".a", 126)
	f = func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccess(
				fcors.FromOrigins(origin),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from pathological disallowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://b" + strings.Repeat(".a", 126)},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from pathological disallowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://b" + strings.Repeat(".a", 126)},
			},
		}, {
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://a" + strings.Repeat(".a", 126)},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://a" + strings.Repeat(".a", 126)},
			},
		},
	}
	middlewares = append(middlewares, mw)

	mw = middleware{name: "allow two pathological origins"}
	originA := "https://a" + strings.Repeat(".a", 126)
	originB := "https://b" + strings.Repeat(".a", 126)
	f = func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccess(
				fcors.FromOrigins(originA, originB),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from pathological disallowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://c" + strings.Repeat(".a", 126)},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from pathological disallowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://c" + strings.Repeat(".a", 126)},
			},
		}, {
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://a" + strings.Repeat(".a", 126)},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://a" + strings.Repeat(".a", 126)},
			},
		},
	}
	middlewares = append(middlewares, mw)

	mw = middleware{name: "allow one origin with credentials with any request headers"}
	f = func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccessWithCredentials(
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyRequestHeaders(),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from allowed origin with adversarial ACRH",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {strings.Join(bigSliceOfJunk(10000), ", ")},
			},
		},
	}
	middlewares = append(middlewares, mw)
	mw = middleware{name: "allow one origin with credentials and expose some response headers"}
	f = func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cors, err = fcors.AllowAccessWithCredentials(
				fcors.FromOrigins("https://example.com"),
				requestHeadersAllowedByDefaultInRsCORS(),
				fcors.ExposeResponseHeaders("foo", "bar", "baz"),
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run(fmt.Sprintf("%s init", mw.name), f)
	mw.cors = cors
	mw.reqs = []request{
		{
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {strings.Join(bigSliceOfJunk(10000), ", ")},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://example.com"},
			},
		},
	}
	middlewares = append(middlewares, mw)

	for _, mw := range middlewares {
		handler := mw.cors(dummyHandler)
		for _, req := range mw.reqs {
			name := fmt.Sprintf("%s vs %s", mw.name, req.name)
			f := func(b *testing.B) {
				req := newRequest(req.method, req.headers)
				recs := makeResponseRecorders(b.N)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					handler.ServeHTTP(recs[i], req)
				}
			}
			b.Run(name, f)
		}
	}
}

// In this unlikely use case, a middleware adding a Vary header is stacked
// on top of a CORS middleware that allows multiple origins.
// As result, we incur a heap allocation when we add a second Vary header;
// see the slow path of the fastAdd function.
func BenchmarkMiddlewareInvocationVary(b *testing.B) {
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.example.com"),
		requestHeadersAllowedByDefaultInRsCORS(),
	)
	if err != nil {
		b.Fatal(err)
	}
	handler := varyMiddleware(cors(dummyHandler))
	reqs := []request{
		{
			name:   "CORS preflight request from allowed origin",
			method: http.MethodOptions,
			headers: http.Header{
				headerOrigin: {"https://foo.example.com"},
				headerACRM:   {http.MethodGet},
				headerACRH:   {"authorization"},
			},
		}, {
			name:   "actual CORS request from allowed origin",
			method: http.MethodGet,
			headers: http.Header{
				headerOrigin: {"https://foo.example.com"},
			},
		},
	}
	for _, req := range reqs {
		name := fmt.Sprintf("allow multiple origins vs %s", req.name)
		f := func(b *testing.B) {
			req := newRequest(req.method, req.headers)
			recs := makeResponseRecorders(b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				handler.ServeHTTP(recs[i], req)
			}
		}
		b.Run(name, f)
	}
}

func makeResponseRecorders(n int) []*httptest.ResponseRecorder {
	recs := make([]*httptest.ResponseRecorder, n)
	for i := 0; i < n; i++ {
		recs[i] = httptest.NewRecorder()
	}
	return recs
}

func bigSliceOfJunk(size int) []string {
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = fmt.Sprintf("foobarbazquxquux-%d", i)
	}
	return out
}
