package fcors_test

import (
	"net/http"
	"testing"

	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/risky"
)

func Test_AllowAccess_From_Any_Origin(t *testing.T) {
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
		dummyMaxAge                 = 0
	)
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		fcors.PreflightSuccessStatus(dummyPreflightSuccessStatus),
		fcors.MaxAgeInSeconds(dummyMaxAge),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	const dummyOrigin = "https://example.com"
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
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
				headerACAO: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from an abnormally long origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{abnormallyLongOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerACMA: []string{stringFromUint(dummyMaxAge)},
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
			name:      "CORS preflight request with disallowed PUT from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: dummyPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccess_From_Any_Origin_With_Any_Method_And_Headers_And_AssumeNoExtendedWildcardSupport(t *testing.T) {
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
	const dummyValidOrigin = "https://example.com"
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		fcors.WithAnyMethod(),
		fcors.WithAnyRequestHeaders(),
		risky.AssumeNoExtendedWildcardSupport(),
	)
	if err != nil {
		t.Errorf("got error with message %q; want nil error", err.Error())
		return
	}
	cases := []TestCase{
		{
			name:           "non-CORS GET request",
			reqMethod:      http.MethodGet,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS GET request from a valid and allowed origin",
			reqMethod: http.MethodGet,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:      "non-preflight CORS OPTIONS request from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
			},
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue, dummyVaryValue},
			},
		}, {
			name:      "CORS preflight request with GET from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodGet},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodPut},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerACAM: []string{http.MethodPut},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with PUT with non-safelisted header names from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodPut},
				headerACRH:   []string{"foo,bar,baz"},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerACAM: []string{http.MethodPut},
				headerACAH: []string{"foo,bar,baz"},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRPN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRPN:  []string{headerValueTrue},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		}, {
			name:      "CORS preflight request with GET with ACRLN from a valid and allowed origin",
			reqMethod: http.MethodOptions,
			reqHeaders: http.Header{
				headerOrigin: []string{dummyValidOrigin},
				headerACRM:   []string{http.MethodGet},
				headerACRLN:  []string{headerValueTrue},
			},
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{wildcard},
				headerVary: []string{varyPreflightValue},
			},
		},
	}
	process(t, cors(dummyHandler), cases)
}
