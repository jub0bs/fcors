// Package risky provides additional options that complement those provided
// by package [github.com/jub0bs/fcors] but that are potentially dangerous.
// Only resort to these options if you must and if you understand
// the consequences of doing so.
package risky

import (
	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/internal"
)

// PrivateNetworkAccess configures a CORS middleware to enable
// [Private Network Access], which is a W3C initiative that
// strengthens the [Same-Origin Policy] by denying clients
// in more public networks (e.g. the public Internet) access
// to less public networks (e.g. localhost)
// and provides a server-side opt-in mechanism for such access.
//
// This option applies to all the origins allowed in the configuration
// of the corresponding middleware.
//
// Using this option in conjunction with option
// [PrivateNetworkAccessInNoCorsModeOnly] in a call to
// [github.com/jub0bs/fcors.AllowAccess] or
// [github.com/jub0bs/fcors.AllowAccessWithCredentials] results in
// a failure to build the corresponding middleware.
//
// [Private Network Access]: https://wicg.github.io/private-network-access/
// [Same-Origin Policy]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
func PrivateNetworkAccess() fcors.Option {
	return internal.PrivateNetworkAccess()
}

// PrivateNetworkAccessInNoCorsModeOnly configures a CORS middleware to
// enable [Private Network Access] but in [no-cors mode] only.
// One use case for this option is given by the
// [link-shortening-service example] in the Private Network Access draft.
//
// This option applies to all the origins allowed in the configuration
// of the corresponding middleware.
//
// Using this option in conjunction with option
// [PrivateNetworkAccess] in a call to [github.com/jub0bs/fcors.AllowAccess]
// or [github.com/jub0bs/fcors.AllowAccessWithCredentials] results in
// a failure to build the corresponding middleware.
//
// [Private Network Access]: https://wicg.github.io/private-network-access/
// [link-shortening-service example]: https://wicg.github.io/private-network-access/#shortlinks
// [no-cors mode]: https://fetch.spec.whatwg.org/#concept-request-mode
func PrivateNetworkAccessInNoCorsModeOnly() fcors.Option {
	return internal.PrivateNetworkAccessInNoCorsModeOnly()
}

// AssumeNoExtendedWildcardSupport configures a CORS middleware to
// eschew the use of the wildcard (*) in the following headers:
//
//   - Access-Control-Allow-Headers
//   - Access-Control-Allow-Methods
//   - Access-Control-Expose-Headers
//
// Use this option to maximize compatibility of your CORS policy
// with older browsers. Be aware that, all other things being equal,
// using this option leads to comparatively larger responses.
//
// Using this option in conjunction with option
// [github.com/jub0bs/fcors.ExposeAllResponseHeaders]
// in a call to [github.com/jub0bs/fcors.AllowAccess]
// results in a failure to build the corresponding middleware.
func AssumeNoExtendedWildcardSupport() fcors.OptionAnon {
	return internal.AssumeNoExtendedWildcardSupport()
}

// AssumeNoWebCachingOfPreflightResponses configures a CORS middleware
// to eschew the use of the [Vary header] in preflight responses.
// Responses to OPTIONS requests are [not meant to be cached] but,
// for better or worse, some caching intermediaries can nevertheless be
// configured to cache such responses.
// To avoid poisoning such caches with inadequate preflight responses,
// [github.com/jub0bs/fcors] by default lists the following header names
// in the Vary header of preflight responses:
//
//   - Access-Control-Request-Headers
//   - Access-Control-Request-Methods
//   - Access-Control-Request-Private-Network
//   - Origin
//
// Use this option if you are absolutely sure that no caching intermediaries
// cache your responses to OPTIONS requests and you want to minimize the size
// of preflight responses.
//
// [Vary header]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
// [not meant to be cached]: https://www.rfc-editor.org/rfc/rfc7231#section-4.3.7
func AssumeNoWebCachingOfPreflightResponses() fcors.Option {
	return internal.AssumeNoWebCachingOfPreflightResponses()
}

// TolerateInsecureOrigins enables you to allow insecure origins
// (i.e. origins whose scheme is http),
// which option [github.com/jub0bs/fcors.FromOrigins] by default prohibits.
// Be aware that allowing insecure origins exposes your clients to
// [active network attacks] that can lead to exfiltration of sensitive data,
// as described by James Kettle in [the talk he gave at AppSec EU 2017].
//
// [active network attacks]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [the talk he gave at AppSec EU 2017]: https://www.youtube.com/watch?v=wgkj4ZgxI4c&t=1305s
func TolerateInsecureOrigins() fcors.Option {
	return internal.TolerateInsecureOrigins()
}

// SkipPublicSuffixCheck enables you to allow all subdomains of some
// [public suffix] (also known as "effective top-level domain"),
// which option [github.com/jub0bs/fcors.FromOrigins] by default prohibits.
// Be aware that allowing all subdomains of a public suffix (e.g. com)
// is dangerous because such domains (e.g. jub0bs-attacker.com) are typically
// registrable by anyone, including attackers.
//
// [public suffix]: https://publicsuffix.org/
func SkipPublicSuffixCheck() fcors.Option {
	return internal.SkipPublicSuffixCheck()
}
