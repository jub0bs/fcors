package internal

import (
	"net/http"
	"testing"
)

func TestThatAllForbiddenHeaderNamesAreByteLowercase(t *testing.T) {
	for name := range discreteForbiddenHeaderNames {
		if byteLowercase(name) != name {
			t.Errorf("forbidden header name %q is not byte-lowercase", name)
		}
	}
}

func TestThatAllForbiddenResponseHeaderNamesAreByteLowercase(t *testing.T) {
	for name := range forbiddenResponseHeaderNames {
		if byteLowercase(name) != name {
			t.Errorf("forbidden response-header name %q is not byte-lowercase", name)
		}
	}
}

func TestThatAllSafelistedResponseHeaderNamesAreByteLowercase(t *testing.T) {
	for name := range safelistedResponseHeaderNames {
		if byteLowercase(name) != name {
			t.Errorf("safelisted response-header name %q is not byte-lowercase", name)
		}
	}
}

// This is important because, otherwise, directly indexing the values
// in http.Header maps would not work as expected.
func TestThatAllRelevantHeaderNamesAreInCanonicalFormat(t *testing.T) {
	headerNames := []string{
		headerOrigin,
		headerRequestMethod,
		headerRequestHeaders,
		headerRequestPrivateNetwork,
		headerAllowMethods,
		headerAllowHeaders,
		headerMageAge,
		headerAllowPrivateNetwork,
		headerAllowOrigin,
		headerAllowCredentials,
		headerExposeHeaders,
		headerVary,
		headerAuthorization,
	}
	for _, name := range headerNames {
		if http.CanonicalHeaderKey(name) != name {
			t.Errorf("header name %q is not in canonical format", name)
		}
	}
}
