package internal

import (
	"net/http"

	"github.com/jub0bs/fcors/internal/util"
)

// see https://fetch.spec.whatwg.org/#forbidden-method
var byteLowercasedForbiddenMethods = util.NewSet(
	"connect",
	"trace",
	"track",
)

// see https://fetch.spec.whatwg.org/#cors-safelisted-method
var safelistedMethods = util.NewSet(
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
)

// see https://fetch.spec.whatwg.org/#methods
func isValidMethod(raw string) bool {
	return isToken(raw)
}
