package internal

import (
	"strings"

	"github.com/jub0bs/fcors/internal/util"
)

// see https://fetch.spec.whatwg.org/#forbidden-header-name
var discreteForbiddenHeaderNames = util.NewSet(
	"accept-charset",
	"accept-encoding",
	byteLowercase(headerRequestHeaders),
	byteLowercase(headerRequestMethod),
	// see https://wicg.github.io/local-network-access/#forbidden-header-names
	byteLowercase(headerRequestLocalNetwork),
	byteLowercase(headerRequestPrivateNetwork),
	"connection",
	"content-length",
	"cookie",
	"cookie2",
	"date",
	"dnt",
	"expect",
	"host",
	"keep-alive",
	byteLowercase(headerOrigin),
	"referer",
	"set-cookie",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
)

// almost always a mistake to allow the following as request headers
// as a result of misunderstanding of the CORS protocol.
var disallowedRequestHeaderNames = util.NewSet(
	byteLowercase(wildcard),
	byteLowercase(headerAllowOrigin),
	byteLowercase(headerAllowCredentials),
	byteLowercase(headerAllowMethods),
	byteLowercase(headerAllowHeaders),
	byteLowercase(headerAllowLocalNetwork),
	byteLowercase(headerAllowPrivateNetwork),
	byteLowercase(headerMageAge),
	byteLowercase(headerExposeHeaders),
)

// almost always a mistake to expose the following as response headers
var disallowedResponseHeaderNames = util.NewSet(
	byteLowercase(wildcard),
	byteLowercase(headerOrigin),
	byteLowercase(headerRequestMethod),
	byteLowercase(headerRequestHeaders),
	byteLowercase(headerRequestPrivateNetwork),
)

// see https://fetch.spec.whatwg.org/#forbidden-response-header-name
var forbiddenResponseHeaderNames = util.NewSet(
	"set-cookie",
	"set-cookie2",
)

// see https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
var safelistedResponseHeaderNames = util.NewSet(
	"cache-control",
	"content-language",
	"content-length",
	"content-type",
	"expires",
	"last-modified",
	"pragma",
)

// see https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
func isValidHeaderName(raw string) bool {
	return isToken(raw)
}

// see https://fetch.spec.whatwg.org/#forbidden-header-name
func isForbiddenRequestHeaderName(name string) bool {
	if discreteForbiddenHeaderNames.Contains(name) {
		return true
	}
	return strings.HasPrefix(name, "proxy-") ||
		strings.HasPrefix(name, "sec-")
}
