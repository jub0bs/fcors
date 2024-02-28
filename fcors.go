/*
Package fcors provides [net/http] middleware for
[Cross-Origin Resource Sharing (CORS)].

To create a CORS middleware that only allows anonymous access,
use the [AllowAccess] function.
To create a CORS middleware that allows both anonymous access and
[credentialed access] (e.g. with [cookies]),
use the [AllowAccessWithCredentials] function.

To avoid negative interference from reverse proxies,
other middleware in the chain, or from the handler at the end of the chain,
follow the rules listed below.
The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" used below
are to be interpreted as described in [RFC 2119].

  - Because [CORS-preflight requests] use [OPTIONS] as their method,
    you SHOULD NOT prevent OPTIONS requests from reaching your CORS middleware.
    Otherwise, preflight requests will not get properly handled
    and browser-based clients will likely experience CORS-related errors.
    The examples provided by this package contain further guidance for avoiding
    such pitfalls.
  - Because [CORS-preflight requests are not authenticated], authentication
    SHOULD NOT take place "ahead of" a CORS middleware
    (e.g. in a reverse proxy or an earlier middleware).
    However, a CORS middleware MAY wrap an authentication middleware.
  - Multiple CORS middleware MUST NOT be stacked.
  - Other middleware (if any) in the chain MUST NOT alter any
    [CORS response headers] that are set by this library's middleware
    and MUST NOT add more [CORS response headers].
  - Other middleware (if any) in the chain SHOULD NOT alter any
    [Vary header] that is set by this library's middleware,
    but they MAY add more Vary headers.

This package provides basic options for configuring a CORS middleware,
but more advanced (and potentially dangerous) options can be found in the
[github.com/jub0bs/fcors/risky] package.

[CORS response headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#the_http_response_headers
[CORS-preflight requests are not authenticated]: https://fetch.spec.whatwg.org/#cors-protocol-and-credentials
[CORS-preflight requests]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
[Cross-Origin Resource Sharing (CORS)]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[OPTIONS]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
[RFC 2119]: https://www.ietf.org/rfc/rfc2119.txt
[Vary header]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
[cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
[credentialed access]: https://fetch.spec.whatwg.org/#concept-request-credentials-mode
*/
package fcors

import (
	"net/http"

	"github.com/jub0bs/fcors/internal"
)

// Middleware is a convenience alias for the type of a function that
// takes a [http.Handler] and returns a [http.Handler].
//
// The middleware provided by this package are, of course,
// safe for concurrent use by multiple goroutines.
type Middleware = func(http.Handler) http.Handler

type (
	// An OptionAnon configures a CORS middleware that only allows anonymous
	// access.
	//
	// You're not meant to implement this interface.
	OptionAnon = internal.OptionAnon
	// An Option configures a CORS middleware that allows both anonymous
	// access and [credentialed access] (e.g. with [cookies]).
	//
	// You're not meant to implement this interface.
	//
	// [cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
	// [credentialed access]: https://fetch.spec.whatwg.org/#concept-request-credentials-mode
	Option = internal.Option
)

// AllowAccess creates a CORS middleware that only allows anonymous access,
// according to the specified options.
// The behavior of the resulting middleware is insensitive to the order
// in which the options that configure it are specified.
//
// AllowAccess requires a single call to option [FromOrigins]
// or option [FromAnyOrigin] as one of its arguments.
//
// Using a given option more than once in a call to AllowAccess
// results in a failure to build the corresponding middleware.
//
// If the specified options are invalid or mutually incompatible, AllowAccess
// returns a nil [Middleware] and some non-nil error. Otherwise, it returns
// a functioning [Middleware] and a nil error.
//
// Any occurrence of a nil option results in a panic.
func AllowAccess(one OptionAnon, others ...OptionAnon) (Middleware, error) {
	return internal.NewMiddleware(false, one, others...)
}

// AllowAccessWithCredentials creates a CORS middleware that allows
// both anonymous access and [credentialed access] (e.g. with [cookies]),
// according to the specified options.
// The behavior of the resulting middleware is insensitive to the order
// in which the options that configure it are specified.
//
// AllowAccessWithCredentials requires a single call to option [FromOrigins]
// as one of its arguments.
//
// Using a given option more than once in a call to AllowAccessWithCredentials
// results in a failure to build the corresponding middleware.
//
// If the specified options are invalid or mutually incompatible,
// AllowAccessWithCredentials returns a nil [Middleware] and some non-nil
// error. Otherwise, it returns a functioning [Middleware] and a nil error.
//
// Any occurrence of a nil option results in a panic.
//
// [cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
// [credentialed access]: https://fetch.spec.whatwg.org/#concept-request-credentials-mode
func AllowAccessWithCredentials(one Option, others ...Option) (Middleware, error) {
	return internal.NewMiddleware(true, one, others...)
}

// FromOrigins configures a CORS middleware to allow access from any of the
// [Web origins] encompassed by the specified origin patterns.
//
// Using this option in conjunction with option [FromAnyOrigin] in a call
// to [AllowAccess] results in a failure to build the corresponding middleware.
// Any occurrence of a prohibited pattern results in a failure to build
// the corresponding middleware.
//
// Permitted schemes are limited to http (with a caveat explained further down)
// and https:
//
//	http://example.com             // permitted
//	https://example.com            // permitted
//	chrome-extension://example.com // prohibited
//
// Origins must be specified in [ASCII serialized form]; Unicode is prohibited:
//
//	https://example.com            // permitted
//	https://www.xn--xample-9ua.com // permitted (Punycode)
//	https://www.éxample.com        // prohibited (Unicode)
//
// For [security reasons], the [null origin] is prohibited.
//
// Hosts that are IPv4 addresses must be specified in [dotted-quad notation]:
//
//	http://255.0.0.0  // permitted
//	http://0xFF000000 // prohibited
//
// Hosts that are IPv6 addresses must be specified in their [compressed form]:
//
//	http://[::1]:9090                                     // permitted
//	http://[0:0:0:0:0:0:0:0001]:9090                      // prohibited
//	http://[0000:0000:0000:0000:0000:0000:0000:0001]:9090 // prohibited
//
// Valid port values range from 1 to 65,535 (inclusive):
//
//	https://example.com       // permitted (no port)
//	https://example.com:1     // permitted
//	https://example.com:65535 // permitted
//	https://example.com:0     // prohibited
//	https://example.com:65536 // prohibited
//
// Default ports (80 for http, 443 for https) must be elided:
//
//	http://example.com      // permitted
//	https://example.com     // permitted
//	http://example.com:80   // prohibited
//	https://example.com:443 // prohibited
//
// In addition to support for exact origins,
// this option provides limited support for origin patterns
// that encompass multiple origins.
// A leading asterisk (followed by a full stop) in a host pattern
// denotes exactly one arbitrary DNS label
// or several period-separated arbitrary DNS labels.
// For instance, the pattern
//
//	https://*.example.com
//
// encompasses the following origins (among others):
//
//	https://foo.example.com
//	https://bar.example.com
//	https://bar.foo.example.com
//	https://baz.bar.foo.example.com
//
// An asterisk in place of a port denotes an arbitrary (possibly implicit)
// port. For instance,
//
//	http://localhost:*
//
// encompasses the following origins (among others),
//
//	http://localhost
//	http://localhost:80
//	http://localhost:9090
//
// Specifying both arbitrary subdomains and arbitrary ports
// in a given origin pattern is prohibited:
//
//	https://*.example.com       // permitted
//	https://*.example.com:9090  // permitted
//	https://example.com:*       // permitted
//	https://*.example.com:*     // prohibited
//
// No other types of origin patterns are supported. In particular,
// an origin pattern consisting of a single asterisk is prohibited.
// If you want to allow (anonymous) access from all origins,
// use option [FromAnyOrigin] instead of this one.
//
// Origins whose scheme is http and whose host is neither localhost
// nor a [loopback IP address] are deemed insecure;
// as such, for [security reasons], they are by default prohibited.
// If you need to deliberately allow insecure origins (danger!),
// you must also activate option
// [github.com/jub0bs/fcors/risky.TolerateInsecureOrigins].
// Any occurrence of an insecure origin without activating option
// [github.com/jub0bs/fcors/risky.TolerateInsecureOrigins]
// results in a failure to build the corresponding middleware.
//
// Also for security reasons, allowing arbitrary subdomains of a base domain
// that happens to be a [public suffix] is by default prohibited:
//
//	https://*.example.com  // permitted: example.com is not a public suffix
//	https://*.com          // prohibited (by default): com is a public suffix
//	https://*.github.io    // prohibited (by default): github.io is a public suffix
//
// If you need to deliberately allow arbitrary subdomains of a
// public suffix (danger!), you must also activate option
// [github.com/jub0bs/fcors/risky.SkipPublicSuffixCheck].
// Any occurrence of such a prohibited origin pattern without activating option
// [github.com/jub0bs/fcors/risky.SkipPublicSuffixCheck]
// results in a failure to build the corresponding middleware.
//
// [ASCII serialized form]: https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
// [compressed form]: https://datatracker.ietf.org/doc/html/rfc5952
// [dotted-quad notation]: https://en.wikipedia.org/wiki/Dot-decimal_notation
// [loopback IP address]: https://www.rfc-editor.org/rfc/rfc5735#section-3
// [null origin]: https://fetch.spec.whatwg.org/#append-a-request-origin-header
// [public suffix]: https://publicsuffix.org/
// [security reasons]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
func FromOrigins(one string, others ...string) Option {
	return internal.FromOrigins(one, others...)
}

// FromAnyOrigin configures a CORS middleware to allow any Web origin.
//
// Using this option in conjunction with option [FromOrigins]
// in a call to [AllowAccess] results in a failure to build the corresponding
// middleware.
func FromAnyOrigin() OptionAnon {
	return internal.FromAnyOrigin()
}

// WithMethods configures a CORS middleware to allow any of the specified
// HTTP methods.
//
// Using this option in conjunction with option [WithAnyMethod] in a call
// to [AllowAccess] or [AllowAccessWithCredentials] results in a failure
// to build the corresponding middleware.
//
// Method names are case-sensitive.
//
// The three so-called "[CORS-safelisted methods]" ([GET], [HEAD], and [POST])
// are by default allowed by the CORS protocol.
// As such, allowing them explicitly in your CORS configuration is
// harmless but never actually necessary.
//
// Moreover, the CORS protocol forbids the use of some method names.
// Accordingly, any occurrence of an [invalid] or [forbidden] method name
// results in a failure to build the corresponding middleware.
//
// Although a valid method name, a literal * is also prohibited;
// to allow all methods, use option [WithAnyMethod]
// instead of this one.
//
// Note that, contrary to popular belief, listing OPTIONS as an allowed method
// in your CORS configuration is only required if you wish to allow clients
// to make explicit use of that method, e.g. via the following client code:
//
//	fetch('https://example.com', {method: 'OPTIONS'})
//
// In the great majority of cases, listing OPTIONS as an allowed method
// in your CORS configuration is unnecessary.
//
// [CORS-safelisted methods]: https://fetch.spec.whatwg.org/#cors-safelisted-method
// [GET]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
// [HEAD]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
// [POST]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
// [forbidden]: https://fetch.spec.whatwg.org/#forbidden-method
// [invalid]: https://fetch.spec.whatwg.org/#methods
func WithMethods(one string, others ...string) Option {
	return internal.WithMethods(one, others...)
}

// WithAnyMethod configures a CORS middleware to allow any HTTP method.
//
// Using this option in conjunction with option [WithMethods] in a call
// to [AllowAccess] or [AllowAccessWithCredentials] results in a failure
// to build the corresponding middleware.
func WithAnyMethod() Option {
	return internal.WithAnyMethod()
}

// WithRequestHeaders configures a CORS middleware to allow any of the
// specified request headers.
//
// Using this option in conjunction with option [WithAnyRequestHeaders]
// in a call to [AllowAccess] or [AllowAccessWithCredentials] results
// in a failure to build the corresponding middleware.
//
// Any occurrence of an [invalid header name] results in a failure to build the
// corresponding middleware.
//
// Header names are case-insensitive.
//
// The CORS protocol defines a number of so-called
// "[forbidden request-header names]", which are never allowed
// and that browsers silently drop from client requests.
// Specifying one or more forbidden request-header name(s) results
// in a failure to build the corresponding middleware.
//
// Finally, some header names that have no place in a request are prohibited:
//
//   - Access-Control-Allow-Credentials
//   - Access-Control-Allow-Headers
//   - Access-Control-Allow-Methods
//   - Access-Control-Allow-Origin
//   - Access-Control-Allow-Private-Network
//   - Access-Control-Expose-Headers
//   - Access-Control-Max-Age
//
// Although a valid request-header name, a literal * is also prohibited;
// to allow all request headers, use option [WithAnyRequestHeaders]
// instead of this one.
//
// [forbidden request-header names]: https://fetch.spec.whatwg.org/#forbidden-request-header
// [invalid header name]: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
func WithRequestHeaders(one string, others ...string) Option {
	return internal.WithRequestHeaders(one, others...)
}

// WithAnyRequestHeaders configures a CORS middleware to allow any request
// headers.
//
// Using this option in conjunction with option [WithRequestHeaders] in a call
// to [AllowAccess] or [AllowAccessWithCredentials] results in a failure to
// build the corresponding middleware.
func WithAnyRequestHeaders() Option {
	return internal.WithAnyRequestHeaders()
}

// MaxAgeInSeconds configures a CORS middleware to instruct browsers to
// cache preflight responses for a maximum duration of delta seconds.
//
// Specifying a max-age value of 0 instructs browsers to eschew caching of
// preflight responses altogether, whereas omitting to specify a max age
// causes browsers to cache preflight responses with a [default max-age value]
// of 5 seconds.
//
// Because all modern browsers cap the max-age value
// (the larger upper bound currently is Firefox's: 86,400 seconds),
// this option accordingly imposes an upper bound on its argument:
// attempts to specify a max-age value larger than 86400
// result in a failure to build the corresponding middleware.
//
// [default max-age value]: https://fetch.spec.whatwg.org/#http-access-control-max-age
func MaxAgeInSeconds(delta uint) Option {
	return internal.MaxAgeInSeconds(delta)
}

// ExposeResponseHeaders configures a CORS middleware to expose the specified
// response headers to the client.
//
// Using this option in conjunction with option [ExposeAllResponseHeaders]
// in a call to [AllowAccess] results in a failure to build the corresponding
// middleware.
//
// Any occurrence of an [invalid header name] results in a failure to build the
// corresponding middleware.
//
// Header names are case-insensitive.
//
// The CORS protocol defines a number of so-called
// "[CORS-safelisted response-header names]", which are always accessible
// to the client.
// The CORS protocol also defines a number of so-called
// "[forbidden response-header names]", which are never accessible to the
// client.
// Specifying one or more safelisted or forbidden response-header
// name(s) results in a failure to build the corresponding middleware.
//
// Finally, some header names that have no place in a response are prohibited:
//
//   - Access-Control-Request-Headers
//   - Access-Control-Request-Method
//   - Access-Control-Request-Private-Network
//   - Origin
//
// Although a valid response-header name, a literal * is also prohibited;
// to expose all response headers, use option [ExposeAllResponseHeaders]
// instead of this one.
//
// [CORS-safelisted response-header names]: https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
// [forbidden response-header names]: https://fetch.spec.whatwg.org/#forbidden-response-header-name
// [invalid header name]: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
func ExposeResponseHeaders(one string, others ...string) Option {
	return internal.ExposeResponseHeaders(one, others...)
}

// ExposeAllResponseHeaders configures a CORS middleware to expose all
// response headers to the client.
//
// Using this option in conjunction with option [ExposeResponseHeaders]
// in a call to [AllowAccess] results in a failure to build the
// corresponding middleware.
func ExposeAllResponseHeaders() OptionAnon {
	return internal.ExposeAllResponseHeaders()
}

// PreflightSuccessStatus configures a CORS middleware to use the specified
// status code in successful preflight responses.
//
// When this option is not used, the status used in successful preflight
// responses is [204 No Content].
//
// Specifying a custom status code outside the [2xx range] results in
// a failure to build the corresponding middleware.
//
// [204 No Content]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204
// [2xx range]: https://fetch.spec.whatwg.org/#ok-status
func PreflightSuccessStatus(code uint) Option {
	return internal.PreflightSuccessStatus(code)
}
