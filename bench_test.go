package fcors_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
)

func BenchmarkMiddlewareInitialization(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fcors.AllowAccessWithCredentials(
			fcors.FromOrigins(
				"https://*.example0.com",
				"https://*.example1.com",
				"https://*.example2.com",
				"https://*.example3.com",
				"https://*.example4.com",
				"https://*.example5.com",
				"https://*.example6.com",
				"https://*.example7.com",
			),
			fcors.WithRequestHeaders("Authorization"),
			fcors.WithMethods(http.MethodPut),
		)
	}
}

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

var requestHeadersAllowedByDefaultInRsCORS = fcors.WithRequestHeaders(
	"Accept",
	"Content-Type",
	"X-Requested-With",
)

func mustAllowAccess(tb testing.TB, one fcors.OptionAnon, others ...fcors.OptionAnon) fcors.Middleware {
	tb.Helper()
	cors, err := fcors.AllowAccess(one, others...)
	if err != nil {
		tb.Fatal("invalid policy")
	}
	return cors
}

func mustAllowAccessWithCredentials(tb testing.TB, one fcors.Option, others ...fcors.Option) fcors.Middleware {
	tb.Helper()
	cors, err := fcors.AllowAccessWithCredentials(one, others...)
	if err != nil {
		tb.Fatal("invalid policy")
	}
	return cors
}

func identity[T any](t T) T { return t }

func BenchmarkMiddlewareInvocation(b *testing.B) {
	var middlewares = []middleware{
		{
			name: "without CORS config",
			cors: identity[http.Handler],
			reqs: []request{
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
			},
		}, {
			name: "allow arbitrary origin",
			cors: mustAllowAccess(
				b,
				fcors.FromAnyOrigin(),
				requestHeadersAllowedByDefaultInRsCORS,
			),
			reqs: []request{
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
			},
		}, {
			name: "allow one origin",
			cors: mustAllowAccess(
				b,
				fcors.FromOrigins("https://example.com"),
				requestHeadersAllowedByDefaultInRsCORS,
			),
			reqs: []request{
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
			},
		}, {
			name: "allow multiple origins",
			cors: mustAllowAccess(
				b,
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
				requestHeadersAllowedByDefaultInRsCORS,
			),
			reqs: []request{
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
			},
		}, {
			name: "allow one pathological origin",
			cors: mustAllowAccess(
				b,
				fcors.FromOrigins(
					"https://a"+strings.Repeat(".a", 126),
				),
			),
			reqs: []request{
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
			},
		}, {
			name: "allow two pathological origins",
			cors: mustAllowAccess(
				b,
				fcors.FromOrigins(
					"https://a"+strings.Repeat(".a", 126),
					"https://b"+strings.Repeat(".a", 126),
				),
			),
			reqs: []request{
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
			},
		}, {
			name: "allow one origin with credentials with any request headers",
			cors: mustAllowAccessWithCredentials(
				b,
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyRequestHeaders(),
			),
			reqs: []request{
				{
					name:   "CORS preflight request from allowed origin with adversarial ACRH",
					method: http.MethodOptions,
					headers: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {strings.Join(bigSliceOfJunk(10000), ", ")},
					},
				},
			},
		}, {
			name: "allow one origin with credentials and expose some response headers",
			cors: mustAllowAccessWithCredentials(
				b,
				fcors.FromOrigins("https://example.com"),
				requestHeadersAllowedByDefaultInRsCORS,
				fcors.ExposeResponseHeaders("foo", "bar", "baz"),
			),
			reqs: []request{
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
			},
		},
	}
	for _, mw := range middlewares {
		handler := mw.cors(dummyHandler)
		for _, req := range mw.reqs {
			name := fmt.Sprintf("%s vs %s", mw.name, req.name)
			f := func(b *testing.B) {
				req := newRequest(req.method, req.headers)
				rec := httptest.NewRecorder()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// important because rec is shared across iterations
					clear(rec.Header())
					handler.ServeHTTP(rec, req)
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
	cors := mustAllowAccess(
		b,
		fcors.FromOrigins("https://*.example.com"),
		requestHeadersAllowedByDefaultInRsCORS,
	)
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
			rec := httptest.NewRecorder()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// important because rec is shared across iterations
				clear(rec.Header())
				handler.ServeHTTP(rec, req)
			}
		}
		b.Run(name, f)
	}
}

// TODO: replace by clear builtin when migrating to Go 1.21
func clear(h http.Header) {
	for k := range h {
		delete(h, k)
	}
}

func bigSliceOfJunk(size int) []string {
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = fmt.Sprintf("foobarbazquxquux-%d", i)
	}
	return out
}
