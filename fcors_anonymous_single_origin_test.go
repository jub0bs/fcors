package fcors_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/risky"
)

func Test_AllowAccess_From_Single_Origin(t *testing.T) {
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
	)
	const allowedOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Origin_With_Method_And_Header_And_Expose_Header(t *testing.T) {
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
	)
	const (
		allowedOrigin         = "https://example.com"
		allowedMethod         = "dummyMethod"
		allowedRequestHeader  = "dummyRequestHeader"
		exposedResponseHeader = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.WithMethods(allowedMethod),
		fcors.WithRequestHeaders(allowedRequestHeader),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Origin_With_Any_Method_And_Headers_And_Expose_All_Headers(t *testing.T) {
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
	const allowedOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.WithAnyMethod(),
		fcors.WithAnyRequestHeaders(),
		fcors.ExposeAllResponseHeaders(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
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
				headerACEH: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			name:      "CORS preflight request with PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAH: []string{"*,authorization"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{wildcard},
				headerACAH: []string{"*,authorization"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{wildcard},
				headerACAH: []string{wildcardAndAuth},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{wildcard},
				headerACAH: []string{wildcardAndAuth},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Origin_With_LocalNetworkAccessInNoCorsModeOnly(t *testing.T) {
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
	)
	const allowedOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		risky.LocalNetworkAccessInNoCorsModeOnly(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
			name:      "CORS preflight request with GET from a valid and allowed origin with",
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACMA:  []string{stringFromUint(dummyMaxAge)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACMA:  []string{stringFromUint(dummyMaxAge)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Origin_With_LocalNetworkAccess(t *testing.T) {
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
	)
	const allowedOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		risky.LocalNetworkAccess(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
			name:      "CORS preflight request with GET from a valid and allowed origin with",
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACMA:  []string{stringFromUint(dummyMaxAge)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACMA:  []string{stringFromUint(dummyMaxAge)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Origin_With_Any_Method_And_Headers_And_AssumeNoExtendedWildcardSupport(t *testing.T) {
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
	const allowedOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.WithAnyMethod(),
		fcors.WithAnyRequestHeaders(),
		risky.AssumeNoExtendedWildcardSupport(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			name:      "CORS preflight request with PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{http.MethodPut},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{allowedOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{http.MethodPut},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{http.MethodPut},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
			expectedStatus: defaultPreflightSuccessStatus,
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAM: []string{http.MethodPut},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Insecure_Origin_With_Method_And_Header_And_Expose_Header(t *testing.T) {
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
	)
	const (
		allowedOrigin         = "http://example.com"
		allowedMethod         = "dummyMethod"
		allowedRequestHeader  = "dummyRequestHeader"
		exposedResponseHeader = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.WithMethods(allowedMethod),
		fcors.WithRequestHeaders(allowedRequestHeader),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
		risky.TolerateInsecureOrigins(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with disallowed PUT from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerACAM: []string{allowedMethod},
				headerACAH: []string{strings.ToLower(allowedRequestHeader)},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Single_Loopback_IP_Address(t *testing.T) {
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
	)
	const allowedOrigin = "http://127.0.0.1:9090"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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

func Test_AllowAccess_From_Localhost(t *testing.T) {
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
	)
	const allowedOrigin = "http://localhost:9090"
	cors, err := fcors.AllowAccess(
		fcors.FromOrigins(allowedOrigin),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const disallowedOrigin = "https://foo.example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid but disallowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
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
				headerACAO: []string{allowedOrigin},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid but disallowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{disallowedOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
				headerOrigin: []string{disallowedOrigin},
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
