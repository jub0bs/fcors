package fcors_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"github.com/jub0bs/fcors/internal/util"
)

const (
	dummyInvalidOrigin   = "https://jub0bs.com/"
	abnormallyLongOrigin = "https://foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz." +
		"foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.foobarbaz.com"

	headerOrigin = "Origin"
	headerACRM   = "Access-Control-Request-Method"
	headerACRH   = "Access-Control-Request-Headers"
	headerACRPN  = "Access-Control-Request-Private-Network"

	headerACAO = "Access-Control-Allow-Origin"
	headerACAC = "Access-Control-Allow-Credentials"

	headerACMA  = "Access-Control-Max-Age"
	headerACAM  = "Access-Control-Allow-Methods"
	headerACAH  = "Access-Control-Allow-Headers"
	headerACAPN = "Access-Control-Allow-Private-Network"
	headerACEH  = "Access-Control-Expose-Headers"
	headerVary  = "Vary"

	varyPreflightValue = headerACRH + ", " + headerACRM + ", " +
		headerACRPN + ", " + headerOrigin

	wildcard                      = "*"
	wildcardAndAuth               = wildcard + ",authorization"
	headerValueTrue               = "true"
	defaultPreflightSuccessStatus = http.StatusNoContent
)

type TestCase struct {
	name                string
	reqMethod           string
	reqHeaders          http.Header
	expectedStatus      int
	expectedRespHeaders http.Header
}

var dummyHandler = http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

var headerVaryBefore = []string{"before"}

var varyMiddleware = func(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		w.Header()[headerVary] = headerVaryBefore
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func process(t *testing.T, handler http.Handler, cases []TestCase) {
	t.Helper()
	for _, c := range cases {
		f := func(t *testing.T) {
			req := newRequest(c.reqMethod, c.reqHeaders)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			res := rec.Result()
			if res.StatusCode != c.expectedStatus {
				t.Errorf("want status %d; got %d", c.expectedStatus, res.StatusCode)
			}
			checkResponseHeaders(t, res.Header, c.expectedRespHeaders)
		}
		t.Run("versus "+c.name, f)
	}
}

func checkResponseHeaders(
	t *testing.T,
	actualHeaders http.Header,
	expectedHeaders http.Header,
) {
	t.Helper()
	unexpectedNames := util.NewSet(
		headerACAO,
		headerACAC,
		headerACAM,
		headerACAH,
		headerACMA,
		headerACAPN,
		headerACEH,
		headerVary,
	)
	for expectedName, expectedValue := range expectedHeaders {
		delete(unexpectedNames, expectedName)
		actualValue, found := actualHeaders[expectedName]
		if !found {
			t.Errorf("absence of expected header %q", expectedName)
			return
		}
		if !slices.Equal(expectedValue, actualValue) {
			const tmpl = "unexpected header value for header %q:\n\tgot %q;\n\twant %q"
			t.Errorf(tmpl, expectedName, actualValue, expectedValue)
		}
	}
	for unwantedName := range unexpectedNames {
		if value, found := actualHeaders[unwantedName]; found {
			const tmpl = "presence of unexpected response header %q: %q"
			t.Errorf(tmpl, unwantedName, value[0])
		}
	}
}

func newRequest(method string, headers http.Header) *http.Request {
	const dummyEndpoint = "https://example.com/whatever"
	req := httptest.NewRequest(method, dummyEndpoint, nil)
	req.Header = headers
	return req
}

func stringFromUint(u uint) string {
	return strconv.FormatUint(uint64(u), 10)
}
