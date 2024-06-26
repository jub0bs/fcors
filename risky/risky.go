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
// [Private-Network Access], which is a W3C initiative that
// strengthens the [Same-Origin Policy] by denying clients
// in more public networks (e.g. the public Internet) access
// to less public networks (e.g. localhost)
// and provides a server-side opt-in mechanism for such access.
//
// This option applies to all the origins allowed in the configuration
// of the corresponding middleware.
//
// Using this option in conjunction with option
// [PrivateNetworkAccessInNoCORSModeOnly] in a call to
// [github.com/jub0bs/fcors.AllowAccess] or
// [github.com/jub0bs/fcors.AllowAccessWithCredentials] results in
// a failure to build the corresponding middleware.
//
// [Private-Network Access]: https://wicg.github.io/private-network-access/
// [Same-Origin Policy]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
func PrivateNetworkAccess() fcors.Option {
	return internal.PrivateNetworkAccess()
}

// PrivateNetworkAccessInNoCORSModeOnly configures a CORS middleware to
// enable [Private-Network Access] but in [no-cors mode] only.
// One use case for this option is given by the
// [link-shortening-service example] in the Private-Network Access draft.
//
// This option applies to all the origins allowed in the configuration
// of the corresponding middleware.
//
// Using this option in conjunction with option
// [PrivateNetworkAccess] in a call to [github.com/jub0bs/fcors.AllowAccess]
// or [github.com/jub0bs/fcors.AllowAccessWithCredentials] results in
// a failure to build the corresponding middleware.
//
// [Private-Network Access]: https://wicg.github.io/private-network-access/
// [link-shortening-service example]: https://wicg.github.io/private-network-access/#shortlinks
// [no-cors mode]: https://fetch.spec.whatwg.org/#concept-request-mode
func PrivateNetworkAccessInNoCORSModeOnly() fcors.Option {
	return internal.PrivateNetworkAccessInNoCORSModeOnly()
}

// DangerouslyTolerateInsecureOrigins enables you to tolerate insecure origins
// (i.e. origins whose scheme is http),
// which option [github.com/jub0bs/fcors.FromOrigins] by default prohibits
// when credentialed access is enabled and/or
// some form of [Private-Network Access] is enabled.
// Be aware that allowing insecure origins exposes your clients to
// [active network attacks] that can lead to exfiltration of sensitive data,
// as described by James Kettle in [the talk he gave at AppSec EU 2017].
//
// [Private-Network Access]: https://wicg.github.io/private-network-access/
// [active network attacks]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [the talk he gave at AppSec EU 2017]: https://www.youtube.com/watch?v=wgkj4ZgxI4c&t=1305s
func DangerouslyTolerateInsecureOrigins() fcors.Option {
	return internal.DangerouslyTolerateInsecureOrigins()
}

// DangerouslyTolerateSubdomainsOfPublicSuffixes enables you to allow all
// subdomains of some [public suffix] (also known as "effective top-level
// domain"), which option [github.com/jub0bs/fcors.FromOrigins] by default
// prohibits. Be aware that allowing all subdomains of a public suffix
// (e.g. com) is dangerous because such domains (e.g. jub0bs-attacker.com)
// are typically registrable by anyone, including attackers.
//
// [public suffix]: https://publicsuffix.org/
func DangerouslyTolerateSubdomainsOfPublicSuffixes() fcors.Option {
	return internal.DangerouslyTolerateSubdomainsOfPublicSuffixes()
}
