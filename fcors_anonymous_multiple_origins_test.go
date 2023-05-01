package fcors_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/risky"
)

func Test_AllowAccess_From_Multiple_Origins_And_Expose_Header(t *testing.T) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// remarkable Vary header value to make sure
		// it isn't suppressed by the middleware
		w.Header().Add(headerVary, dummyVaryValue)
		w.WriteHeader(dummyStatusCode)
	})
	const (
		dummyPreflightSuccessStatus = 279
		dummyMaxAge                 = 30
		exposedResponseHeader       = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.example.com"),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const (
		allowedOrigin        = "https://foo.example.com"
		disallowedBaseOrigin = "https://example.com"
	)
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an invalid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long and disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an invalid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an abnormally long and disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccess_From_Multiple_Origins_And_Expose_Header_With_LocalNetworkAccess(t *testing.T) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// remarkable Vary header value to make sure
		// it isn't suppressed by the middleware
		w.Header().Add(headerVary, dummyVaryValue)
		w.WriteHeader(dummyStatusCode)
	})
	const (
		dummyPreflightSuccessStatus = 279
		dummyMaxAge                 = 30
		exposedResponseHeader       = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.example.com"),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
		risky.LocalNetworkAccess(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const (
		allowedOrigin        = "https://foo.example.com"
		disallowedBaseOrigin = "https://example.com"
	)
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an invalid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long and disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an invalid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an abnormally long and disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO:  []string{allowedOrigin},
				headerACAPN: []string{headerValueTrue},
				headerACMA:  []string{stringFromUint(30)},
				headerVary:  []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO:  []string{allowedOrigin},
				headerACALN: []string{headerValueTrue},
				headerACMA:  []string{stringFromUint(30)},
				headerVary:  []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccess_From_Multiple_Origins_And_Expose_Header_With_LocalNetworkAccessInNoCorsModeOnly(t *testing.T) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// remarkable Vary header value to make sure
		// it isn't suppressed by the middleware
		w.Header().Add(headerVary, dummyVaryValue)
		w.WriteHeader(dummyStatusCode)
	})
	const (
		dummyPreflightSuccessStatus = 279
		dummyMaxAge                 = 30
		exposedResponseHeader       = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.example.com"),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
		risky.LocalNetworkAccessInNoCorsModeOnly(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const (
		allowedOrigin        = "https://foo.example.com"
		disallowedBaseOrigin = "https://example.com"
	)
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an invalid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long and disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an invalid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an abnormally long and disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO:  []string{allowedOrigin},
				headerACAPN: []string{headerValueTrue},
				headerACMA:  []string{stringFromUint(30)},
				headerVary:  []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO:  []string{allowedOrigin},
				headerACALN: []string{headerValueTrue},
				headerACMA:  []string{stringFromUint(30)},
				headerVary:  []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccess_From_Multiple_Origins_And_AssumeNoWebCachingOfPreflightResponses(t *testing.T) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// remarkable Vary header value to make sure
		// it isn't suppressed by the middleware
		w.Header().Add(headerVary, dummyVaryValue)
		w.WriteHeader(dummyStatusCode)
	})
	const (
		dummyPreflightSuccessStatus = 279
		dummyMaxAge                 = 30
		exposedResponseHeader       = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.example.com"),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		risky.AssumeNoWebCachingOfPreflightResponses(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const (
		allowedOrigin        = "https://foo.example.com"
		disallowedBaseOrigin = "https://example.com"
	)
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an invalid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long and disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with GET from an invalid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with GET from an abnormally long and disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccess_From_Subdomains_Of_Public_Suffix(t *testing.T) {
	const (
		dummyVaryValue  = "whatever"
		dummyStatusCode = 299
	)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// remarkable Vary header value to make sure
		// it isn't suppressed by the middleware
		w.Header().Add(headerVary, dummyVaryValue)
		w.WriteHeader(dummyStatusCode)
	})
	const (
		dummyPreflightSuccessStatus = 279
		dummyMaxAge                 = 30
		exposedResponseHeader       = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins("https://*.com"),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		risky.SkipPublicSuffixCheck(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const (
		allowedOrigin        = "https://example.com"
		disallowedBaseOrigin = "https://example.co.uk"
	)
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an invalid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long and disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{headerOrigin, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an invalid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyInvalidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from an abnormally long and disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedBaseOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: http.StatusForbidden,
			expectedRespHeaders: http.Header{
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}
