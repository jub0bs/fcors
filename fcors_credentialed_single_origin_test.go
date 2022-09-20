package fcors_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
)

func Test_AllowAccessWithCredentials_From_Single_Origin(t *testing.T) {
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
	cors, err := fcors.AllowAccessWithCredentials(
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
				headerACAC: []string{headerValueTrue},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccessWithCredentials_From_Single_Origin_With_Method_And_Header_And_Expose_Header(t *testing.T) {
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
	cors, err := fcors.AllowAccessWithCredentials(
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
				headerACAC: []string{headerValueTrue},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
		},
	}
	process(t, cors(dummyHandler), cases)
}

func Test_AllowAccessWithCredentials_From_Single_Origin_With_Any_Method_And_Headers_And_Expose_Header(t *testing.T) {
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
		allowedOrigin         = "https://example.com"
		exposedResponseHeader = "dummyResponseHeader"
	)
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins(allowedOrigin),
		fcors.WithAnyMethod(),
		fcors.WithAnyRequestHeaders(),
		fcors.ExposeResponseHeaders(exposedResponseHeader),
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
				headerACAC: []string{headerValueTrue},
				headerACEH: []string{strings.ToLower(exposedResponseHeader)},
				headerVary: []string{dummyVaryValue},
			},
		}, {
			name:           "non-CORS OPTIONS request",
			reqMethod:      http.MethodOptions,
			expectedStatus: dummyStatusCode,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
			expectedStatus: defaultPreflightSuccessStatus,
			expectedRespHeaders: http.Header{
				headerACAO: []string{allowedOrigin},
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
				headerACAC: []string{headerValueTrue},
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
		},
	}
	process(t, cors(dummyHandler), cases)
}
