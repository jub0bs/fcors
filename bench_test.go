package fcors_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
)

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	w.Header().Add(headerVary, dummyVaryValue)
	w.WriteHeader(dummyStatusCode)
})

var requestHeadersAllowedByDefaultInRsCORS = fcors.WithRequestHeaders(
	"Accept",
	"Content-Type",
	"X-Requested-With",
)

func BenchmarkStartup(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := fcors.AllowAccessWithCredentials(
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
			fcors.WithRequestHeaders("authorization"),
			fcors.WithMethods("PUT"),
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func BenchmarkWithout(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, dummyEndpoint, nil)
	req.Header.Add(headerOrigin, "https://jub0bs.com")
	res := httptest.NewRecorder()
	handler := dummyHandler

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkActualAllowAnyOrigin(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	req.Header.Add(headerOrigin, "https://example.com")
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkActualAllowSingleOrigin(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, dummyEndpoint, nil)
	const origin = "https://example.com"
	req.Header.Add(headerOrigin, origin)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(origin),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowMultipleOriginsFails(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	const origin = "https://exzxcample.com"
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(
			"https://example.com",
			"https://google.com",
			"https://twitter.com",
			"https://stackoverflow.com",
			"https://reddit.com",
			"https://quora.com",
			"https://example.co.uk",
			"https://google.co.uk",
			"https://twitter.co.uk",
			"https://stackoverflow.co.uk",
			"https://reddit.co.uk",
			"https://quora.co.uk",
			"https://example.com.au",
			"https://google.com.au",
			"https://twitter.com.au",
			"https://stackoverflow.com.au",
			"https://reddit.com.au",
			"https://quora.com.au",
			"https://example.fr",
			"https://google.fr",
			"https://twitter.fr",
			"https://stackoverflow.fr",
			"https://reddit.fr",
			"https://quora.fr",
		),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkActualAllowMultipleBaseOriginsFails(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, dummyEndpoint, nil)
	req.Header.Add(headerOrigin, "https://attacker.com")
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(
			"https://*.example.com",
			"https://*.google.com",
			"https://*.twitter.com",
			"https://*.stackoverflow.com",
			"https://*.reddit.com",
			"https://*.quora.com",
		),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkActualAbnormallyLongOrigin(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, dummyEndpoint, nil)
	const abnormallyLongOrigin = "https://foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.com"
	req.Header.Add(headerOrigin, abnormallyLongOrigin)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(
			"https://*.example.com",
			"https://*.google.com",
			"https://*.twitter.com",
			"https://*.stackoverflow.com",
			"https://*.reddit.com",
			"https://*.quora.com",
		),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowAnyOrigin(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	const origin = "https://example.com"
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowAnyOriginWithPutAndExposeHeaders(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	const origin = "https://example.com"
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodPut)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		fcors.WithMethods(http.MethodPut),
		requestHeadersAllowedByDefaultInRsCORS,
		fcors.ExposeResponseHeaders("foo", "bar", "baz"),
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowMultipleBaseOriginsFails(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	req.Header.Add(headerOrigin, "https://attacker.com")
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
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
			"https://*.example1.com",
			"https://*.google1.com",
			"https://*.twitter1.com",
			"https://*.stackoverflow1.com",
			"https://*.reddit1.com",
			"https://*.quora1.com",
			"https://*.example1.co.uk",
			"https://*.google1.co.uk",
			"https://*.twitter1.co.uk",
			"https://*.stackoverflow1.co.uk",
			"https://*.reddit1.co.uk",
			"https://*.quora1.co.uk",
			"https://*.example1.com.au",
			"https://*.google1.com.au",
			"https://*.twitter1.com.au",
			"https://*.stackoverflow1.com.au",
			"https://*.reddit1.com.au",
			"https://*.quora1.com.au",
			"https://*.example1.fr",
			"https://*.google1.fr",
			"https://*.twitter1.fr",
			"https://*.stackoverflow1.fr",
			"https://*.reddit1.fr",
			"https://*.quora1.fr",
		),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowMultipleBaseOriginsSucceeds(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	req.Header.Add(headerOrigin, "https://foo.quora.fr")
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
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
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowMultipleBaseOriginsFails2(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	req.Header.Add(headerOrigin, "https://attacker.com")
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	const nbSpecs = 1000
	specs := make([]string, nbSpecs)
	for i := 0; i < nbSpecs; i++ {
		specs[i] = fmt.Sprintf("https://*.example%d.com", i)
	}
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(specs[0], specs[1:]...),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAllowAnyOriginWithSingleHeader(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	const origin = "https://example.com"
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	req.Header.Add("Access-Control-Request-Headers", "Accept")
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		requestHeadersAllowedByDefaultInRsCORS,
	)
	if err != nil {
		b.Error(err)
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightAdversarialACRH(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	const origin = "https://example.com"
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	adversarialACRH := strings.Join(bigSliceOfJunk(10000), ", ")
	req.Header.Add("Access-Control-Request-Headers", adversarialACRH)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins(origin),
		fcors.WithAnyRequestHeaders(),
	)
	if err != nil {
		b.Error(err.Error())
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkPreflightPathologicalCaseForCorpus(b *testing.B) {
	req := httptest.NewRequest(http.MethodOptions, dummyEndpoint, nil)
	origin := "https://a" + strings.Repeat(".a", 126)
	req.Header.Add(headerOrigin, origin)
	req.Header.Add("Access-Control-Request-Method", http.MethodGet)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins("https://b"+strings.Repeat(".a", 126)),
		fcors.WithAnyRequestHeaders(),
	)
	if err != nil {
		b.Error(err.Error())
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkActualPathologicalCaseForCorpus(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, dummyEndpoint, nil)
	origin := "https://a" + strings.Repeat(".a", 126)
	req.Header.Add(headerOrigin, origin)
	res := httptest.NewRecorder()
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins("https://b"+strings.Repeat(".a", 126)),
		fcors.WithAnyRequestHeaders(),
	)
	if err != nil {
		b.Error(err.Error())
		return
	}
	handler := cors(http.HandlerFunc(dummyHandler))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func bigSliceOfJunk(size int) []string {
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = fmt.Sprintf("foobarbazquxquux-%d", i)
	}
	return out
}
