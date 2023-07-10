/*
Package fcors provides [net/http] middleware for
[Cross-Origin Resource Sharing (CORS)].

For things to work properly, fcors users must follow certain rules;
the key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" below
are to be interpreted as described in [RFC 2119]:

  - Because [CORS-preflight requests] use [OPTIONS] as their method,
    the resources to which you apply a CORS middleware
    SHOULD accept OPTIONS requests.
  - Because CORS-preflight requests are not authenticated,
    a CORS middleware SHOULD be stacked on top of any authentication middleware.
  - Multiple CORS middleware MUST NOT be stacked; in other words,
    no more than one CORS middleware MUST be used per resource.
  - Other middleware (if any) in the chain MUST NOT alter any
    [CORS response headers] that are set by this library's middleware
    and MUST NOT add more [CORS response headers].
  - Other middleware (if any) in the chain SHOULD NOT alter any
    [Vary header] that is set by this library's middleware,
    but it MAY add more Vary headers.

The package provides basic options for configuring a CORS middleware,
but more advanced (and potentially dangerous) options can be found in the
[github.com/jub0bs/fcors/risky] package.

CORS middleware provided by this package are, of course, safe for concurrent
use by multiple goroutines.

[CORS response headers]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#the_http_response_headers
[CORS-preflight requests]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
[Cross-Origin Resource Sharing (CORS)]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[OPTIONS]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
[RFC 2119]: https://www.ietf.org/rfc/rfc2119.txt
[Vary header]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
*/
package fcors

import (
	"net/http"

	"github.com/jub0bs/fcors/internal"
)

// Middleware is a convenience alias for the type of a function that
// takes a [http.Handler] and returns a [http.Handler].
type Middleware = func(http.Handler) http.Handler

type (
	// An OptionAnon configures a CORS middleware that only allows anonymous
	// access (i.e. without credentials).
	//
	// You're not meant to implement this interface.
	OptionAnon = internal.OptionAnon
	// An OptionAnon configures a CORS middleware that allows credentialed
	// access (i.e. with credentials).
	//
	// You're not meant to implement this interface.
	OptionCred = internal.OptionCred
	// An Option configures a CORS middleware, regardless of whether that
	// middleware allows access with credentials. As such, an Option is
	// both an [OptionAnon] and an [OptionCred].
	//
	// You're not meant to implement this interface.
	Option = internal.Option
)

// AllowAccess configures a CORS middleware that only allows anonymous access,
// according to the specified options.
// The behavior of the resulting middleware is insensitive to the order
// in which the options that configure it are specified.
//
// AllowAccess requires a single call to option [FromOrigins]
// or option [FromAnyOrigin] as one of its arguments.
//
// If the specified options are invalid or mutually incompatible, AllowAccess
// returns a nil [Middleware] and some non-nil error. Otherwise, it returns
// a functioning [Middleware] and a nil error.
//
// Any occurrence of a nil option results in a panic.
func AllowAccess(one OptionAnon, others ...OptionAnon) (Middleware, error) {
	return internal.AllowAccess(one, others...)
}

// AllowAccessWithCredentials configures a CORS middleware that allows
// credentialed access (e.g. with [cookies]),
// according to the specified options.
// The behavior of the resulting middleware is insensitive to the order
// in which the options that configure it are specified.
//
// AllowAccessWithCredentials requires a single call to option [FromOrigins]
// as one of its arguments.
//
// If the specified options are invalid or mutually incompatible,
// AllowAccessWithCredentials returns a nil [Middleware] and some non-nil
// error. Otherwise, it returns a functioning [Middleware] and a nil error.
//
// Any occurrence of a nil option results in a panic.
//
// [cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
func AllowAccessWithCredentials(one OptionCred, others ...OptionCred) (Middleware, error) {
	return internal.AllowAccessWithCredentials(one, others...)
}

// FromOrigins configures a CORS middleware to allow access from any of the
// [Web origins] encompassed by the specified origin patterns.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [FromAnyOrigin] in a call
// to [AllowAccess] results in a failure to build the corresponding middleware.
// Any occurrence of an illegal pattern results in a failure to build
// the corresponding middleware.
//
// Legal schemes are limited to http (with a caveat explained further down)
// and https:
//
//	http://example.com             // legal
//	https://example.com            // legal
//	chrome-extension://example.com // illegal
//
// Origins must be specified in [ASCII serialized form]; Unicode is illegal:
//
//	https://example.com            // legal
//	https://www.xn--xample-9ua.com // legal (Punycode)
//	https://www.éxample.com        // illegal (Unicode)
//
// For security reasons, the [null origin] is illegal.
//
// Hosts that are IPv4 addresses must be specified in [dotted-quad notation]:
//
//	http://255.0.0.0  // legal
//	http://0xFF000000 // illegal
//
// Hosts that are IPv6 addresses must be specified in their [compressed form]:
//
//	http://[::1]:9090                                     // legal
//	http://[0:0:0:0:0:0:0:0001]:9090                      // illegal
//	http://[0000:0000:0000:0000:0000:0000:0000:0001]:9090 // illegal
//
// Default ports (80 for http, 443 for https) must be elided:
//
//	http://example.com      // legal
//	http://example.com:80   // illegal
//	https://example.com     // legal
//	https://example.com:443 // illegal
//
// In addition to support for exact origins,
// this option provides limited support for origin patterns
// that encompass multiple origins.
// A leading asterisk (followed by a full stop) in a host pattern
// denotes exactly one arbitrary DNS label. For instance,
//
//	https://*.example.com
//
// encompasses the following origins (among others),
//
//	https://foo.example.com
//	https://bar.example.com
//
// but not
//
//	https://bar.foo.example.com
//
// Two leading asterisks (followed by a full stop) in a host pattern
// denote one or more arbitrary DNS label(s). For instance,
//
//	https://**.example.com
//
// encompasses the following origins (among others),
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
// in a given origin pattern is illegal:
//
//	https://*.example.com:*     // illegal
//	https://**.example.com:*    // illegal
//	https://*.example.com       // legal
//	https://**.example.com      // legal
//	https://*.example.com:9090  // legal
//	https://**.example.com:9090 // legal
//	https://example.com:*       // legal
//
// No other types of origin patterns are supported.
// In particular, a single asterisk is not a legal origin pattern.
// If you want to allow (anonymous) access from all origins,
// use option [FromAnyOrigin] instead of this one.
//
// Origins whose scheme is http and whose host is neither localhost
// nor a [loopback IP address] are deemed insecure;
// as such, they are by default prohibited.
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
//	https://*.com          // prohibited (by default): com is a public suffix
//	https://**.com         // prohibited (by default): com is a public suffix
//	https://*.github.io    // prohibited (by default): github.io is a public suffix
//	https://**.github.io   // prohibited (by default): github.io is a public suffix
//	https://*.example.com  // ok
//	https://**.example.com // ok
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
// [null origin]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
// [public suffix]: https://publicsuffix.org/
func FromOrigins(one string, others ...string) Option {
	return internal.FromOrigins(one, others...)
}

// FromAnyOrigin configures a CORS middleware to allow any Web origin.
//
// Using this option more than once in a call to [AllowAccess] results in a
// failure to build the corresponding middleware.
// Using this option in conjunction with option [FromOrigins]
// in a call to [AllowAccess] results in a failure to build the corresponding
// middleware.
func FromAnyOrigin() OptionAnon {
	return internal.FromAnyOrigin()
}

// WithMethods configures a CORS middleware to allow any of the specified
// HTTP methods.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [WithAnyMethod] in a call
// to [AllowAccess] results in a failure to build the corresponding middleware.
//
// Method names are case-sensitive.
//
// The three so-called "[CORS-safelisted methods]"" ([GET], [HEAD], and [POST])
// are by default allowed by the CORS protocol.
// As such, allowing them explicitly in your CORS configuration is
// harmless but never actually necessary.
//
// Moreover, the CORS protocol forbids the use of some method names.
// Accordingly, any occurrence of an [illegal] or [forbidden] method name
// results in a failure to build the corresponding middleware.
//
// Although a valid method name, a literal * is also prohibited;
// to allow all methods, use option [WithAnyMethod]
// instead of this one.
//
// Note that, contrary to popular belief, configuring a CORS middleware
// to allow the OPTIONS method is only required if some clients actually
// make explicit use of that method, e.g.
//
//	fetch('https://example.com', {method: 'OPTIONS'})
//
// In the great majority of cases, allowing the OPTIONS method is unnecessary.
//
// [CORS-safelisted methods]: https://fetch.spec.whatwg.org/#cors-safelisted-method
// [GET]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
// [HEAD]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
// [POST]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
// [forbidden]: https://fetch.spec.whatwg.org/#forbidden-method
// [illegal]: https://fetch.spec.whatwg.org/#methods
func WithMethods(one string, others ...string) Option {
	return internal.WithMethods(one, others...)
}

// WithAnyMethod configures a CORS middleware to allow any HTTP method.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [WithMethods] in a call
// to [AllowAccess] results in a failure to build the corresponding middleware.
func WithAnyMethod() Option {
	return internal.WithAnyMethod()
}

// WithRequestHeaders configures a CORS middleware to allow all of the
// specified request headers to the client.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [WithAnyRequestHeaders]
// in a call to [AllowAccess] results in a failure to build the corresponding
// middleware.
//
// Any occurrence of an [illegal header name] results in a failure to build the
// corresponding middleware.
//
// Header names are case-insensitive.
// Specifying the same header name multiple times
// (possibly using different cases)
// results in a failure to build the corresponding middleware.
//
// The CORS protocol defines a number of so-called
// "[forbidden request-header names]", which are never allowed
// and get silently dropped by browsers.
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
// [illegal header name]: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
func WithRequestHeaders(one string, others ...string) Option {
	return internal.WithRequestHeaders(one, others...)
}

// WithAnyRequestHeaders configures a CORS middleware to allow any request
// headers.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [WithRequestHeaders] in a call
// to [AllowAccess] results in a failure to build the corresponding middleware.
func WithAnyRequestHeaders() Option {
	return internal.WithAnyRequestHeaders()
}

// MaxAgeInSeconds configures a CORS middleware to intruct browsers to
// cache preflight responses for a maximum duration of delta seconds.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
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
// [default max-age value]: https://fetch.spec.whatwg.org/#http-access-control-max-age.
func MaxAgeInSeconds(delta uint) Option {
	return internal.MaxAgeInSeconds(delta)
}

// ExposeResponseHeaders configures a CORS middleware to expose all of the
// specified response headers to the client.
//
// Using this option more than once in a call to [AllowAccess] or
// [AllowAccessWithCredentials] results in a failure to build the
// corresponding middleware.
// Using this option in conjunction with option [ExposeAllResponseHeaders]
// in a call to [AllowAccess] results in a failure to build the corresponding
// middleware.
//
// Any occurrence of an [illegal header name] results in a failure to build the
// corresponding middleware.
//
// Header names are case-insensitive.
// Specifying the same header name multiple times
// (possibly using different cases)
// results in a failure to build the corresponding middleware.
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
// [illegal header name]: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
func ExposeResponseHeaders(one string, others ...string) Option {
	return internal.ExposeResponseHeaders(one, others...)
}

// ExposeAllResponseHeaders configures a CORS middleware to expose all
// response headers.
//
// Using this option more than once in a call to [AllowAccess] results in
// a failure to build the corresponding middleware.
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
