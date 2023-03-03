package fcors_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/risky"
)

// These tests are only meant as a sanity check, not as a license
// to depend on the precise wording of the various error messages.
func TestInvalidPoliciesForAllowAccess(t *testing.T) {
	policies := []struct {
		desc     string
		options  []fcors.OptionAnon
		errorMsg string
	}{
		{
			desc:     "specified origin contains whitespace",
			options:  []fcors.OptionAnon{fcors.FromOrigins(" http://example.com:6060 ")},
			errorMsg: `fcors: invalid or unsupported scheme: " http://example.com:6060 "`,
		}, {
			desc:    "specified origin is insecure",
			options: []fcors.OptionAnon{fcors.FromOrigins("http://example.com:6060")},
			errorMsg: `fcors: most origin patterns like "http://example.com:6060" that use ` +
				`insecure scheme "http" are by default prohibited`,
		}, {
			desc:     "specified origin's host is an invalid IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://[::1]1:6060"`,
		}, {
			desc:     "specified origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://[::1]:6060")},
			errorMsg: `fcors: scheme "https" incompatible with an IP address: "https://[::1]:6060"`,
		}, {
			desc:     "specified origin is the null origin",
			options:  []fcors.OptionAnon{fcors.FromOrigins("null")},
			errorMsg: `fcors: unsupported "null" origin`,
		}, {
			desc:     "specified origin contains an invalid scheme",
			options:  []fcors.OptionAnon{fcors.FromOrigins("httpsfoo://example.com:6060")},
			errorMsg: `fcors: invalid or unsupported scheme: "httpsfoo://example.com:6060"`,
		}, {
			desc:     "specified origin contains a userinfo",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://user:password@example.com:6060")},
			errorMsg: `fcors: invalid port pattern: "https://user:password@example.com:6060"`,
		}, {
			desc:     "specified origin contains a path",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060/foo")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060/foo"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060?")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060?"`,
		}, {
			desc:     "specified origin contains a querystring",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a fragment",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060#index")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060#index"`,
		}, {
			desc:     "specified origin contains an invalid port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:66536")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:66536"`,
		}, {
			desc:     "specified origin contains a 5-digit port that starts with a nonzero digit",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:06060")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:06060"`,
		}, {
			desc:     "specified origin contains a colon but no port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:"`,
		}, {
			desc:     "specified origin's host contains two trailing full stops",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com..")},
			errorMsg: `fcors: invalid origin pattern: "https://example.com.."`,
		}, {
			desc: "an origin is specified multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"https://example.com:6060",
					"https://example.com:6060",
				),
			},
			errorMsg: `fcors: origin pattern "https://example.com:6060" specified multiple times`,
		}, {
			desc:     "misplaced subdomain pattern",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://foo.*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://foo.*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains whitespace",
			options:  []fcors.OptionAnon{fcors.FromOrigins(" http://*.example.com:6060 ")},
			errorMsg: `fcors: invalid or unsupported scheme: " http://*.example.com:6060 "`,
		}, {
			desc:    "specified base origin is insecure",
			options: []fcors.OptionAnon{fcors.FromOrigins("http://*.example.com:6060")},
			errorMsg: `fcors: most origin patterns like "http://*.example.com:6060" that use ` +
				`insecure scheme "http" are by default prohibited`,
		}, {
			desc:     "specified base origin's host is an invalid IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://*.[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://*.[::1]1:6060"`,
		}, {
			desc:     "specified base origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.[::1]:6060")},
			errorMsg: `fcors: invalid origin pattern: "https://*.[::1]:6060"`,
		}, {
			desc:     "specified base origin's host is an IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://*.127.0.0.1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://*.127.0.0.1:6060"`,
		}, {
			desc:     "specified base origin contains an invalid scheme",
			options:  []fcors.OptionAnon{fcors.FromOrigins("httpsfoo://*.example.com:6060")},
			errorMsg: `fcors: invalid or unsupported scheme: "httpsfoo://*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a userinfo",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://user:password@*.example.com:6060")},
			errorMsg: `fcors: invalid port pattern: "https://user:password@*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a path",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060/foo")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060/foo"`,
		}, {
			desc:     "specified base origin contains a querystring",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060?")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060?"`,
		}, {
			desc:     "specified base origin contains a fragment",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060#index")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060#index"`,
		}, {
			desc:     "specified base origin contains an invalid port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:66536")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:66536"`,
		}, {
			desc:     "specified base origin contains a colon but no port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:"`,
		}, {
			desc:     "specified base origin's host contains two trailing full stops",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com..")},
			errorMsg: `fcors: invalid origin pattern: "https://*.example.com.."`,
		}, {
			desc: "a base origin is specified multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"https://*.example.com:6060",
					"https://*.example.com:6060",
				),
			},
			errorMsg: `fcors: origin pattern "https://*.example.com:6060" specified multiple times`,
		}, {
			desc: "invalid second origin pattern",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"https://example.com",
					"https://*.127.0.0.1:6060",
				),
			},
			errorMsg: `fcors: invalid origin pattern: "https://*.127.0.0.1:6060"`,
		}, {
			desc:    "specified base origin's host is a public suffix",
			options: []fcors.OptionAnon{fcors.FromOrigins("https://*.github.io")},
			errorMsg: `fcors: origin patterns like "https://*.github.io" that allow arbitrary ` +
				`subdomains of public suffix "github.io" are by default prohibited`,
		}, {
			desc:     "missing call to FromOrigins or FromAnyOrigin",
			options:  []fcors.OptionAnon{fcors.WithAnyMethod()},
			errorMsg: `fcors: missing call to FromOrigins or FromAnyOrigin in AllowAccess`,
		}, {
			desc: "empty method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods(""),
			},
			errorMsg: `fcors: invalid method name ""`,
		}, {
			desc: "illegal chars in method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods("résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "wildcard method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods("*"),
			},
			errorMsg: `fcors: disallowed method name "*"`,
		}, {
			desc: "invalid second method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods("foo", "résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "forbidden method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods(http.MethodConnect),
			},
			errorMsg: `fcors: forbidden method name "` + http.MethodConnect + `"`,
		}, {
			desc: "same method name specified multiple times",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods(http.MethodGet, http.MethodGet),
			},
			errorMsg: `fcors: method name "` + http.MethodGet + `" specified multiple times`,
		}, {
			desc: "empty request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders(""),
			},
			errorMsg: `fcors: invalid request-header name ""`,
		}, {
			desc: "illegal chars in request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "wildcard request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("*"),
			},
			errorMsg: `fcors: disallowed request-header name "*"`,
		}, {
			desc: "invalid second request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "forbidden request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("connection"),
			},
			errorMsg: `fcors: forbidden request-header name "connection"`,
		}, {
			desc: "forbidden request-header name Sec-Foo",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("Sec-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "sec-foo"`,
		}, {
			desc: "forbidden request-header name Proxy-Foo",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("Proxy-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "proxy-foo"`,
		}, {
			desc: "same request-header name specified multiple times",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("Foo", "Foo"),
			},
			errorMsg: `fcors: request-header name "foo" specified multiple times`,
		}, {
			desc: "disallowed request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("access-control-allow-origin"),
			},
			errorMsg: `fcors: disallowed request-header name "access-control-allow-origin"`,
		}, {
			desc: "max age exceeds upper bound",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.MaxAgeInSeconds(86401),
			},
			errorMsg: `fcors: specified max-age value 86401 exceeds upper bound 86400`,
		}, {
			desc: "empty response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders(""),
			},
			errorMsg: `fcors: invalid response-header name ""`,
		}, {
			desc: "illegal chars in response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: disallowed response-header name "*"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: disallowed response-header name "*"`,
		}, {
			desc: "invalid second response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "forbidden response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("set-cookie"),
			},
			errorMsg: `fcors: forbidden response-header name "set-cookie"`,
		}, {
			desc: "same response-header name specified multiple times",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("Foo", "Foo"),
			},
			errorMsg: `fcors: response-header name "foo" specified multiple times`,
		}, {
			desc: "disallowed response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("access-control-request-method"),
			},
			errorMsg: `fcors: disallowed response-header name "access-control-request-method"`,
		}, {
			desc: "safelisted response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("cache-control"),
			},
			errorMsg: `fcors: response-header name "cache-control" needs not be explicitly exposed`,
		}, {
			desc: "option FromOrigins used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.FromOrigins("https://example.co.uk"),
			},
			errorMsg: `fcors: option FromOrigins used multiple times`,
		}, {
			desc: "option FromAnyOrigin used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.FromAnyOrigin(),
			},
			errorMsg: `fcors: option FromAnyOrigin used multiple times`,
		}, {
			desc: "option WithMethods used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithMethods(http.MethodPost),
			},
			errorMsg: `fcors: option WithMethods used multiple times`,
		}, {
			desc: "option WithAnyMethod used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyMethod(),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: option WithAnyMethod used multiple times`,
		}, {
			desc: "option WithRequestHeaders used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("foo"),
				fcors.WithRequestHeaders("bar"),
			},
			errorMsg: `fcors: option WithRequestHeaders used multiple times`,
		}, {
			desc: "option WithAnyRequestHeaders used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyRequestHeaders(),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: option WithAnyRequestHeaders used multiple times`,
		}, {
			desc: "option MaxAgeInSeconds used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.MaxAgeInSeconds(30),
				fcors.MaxAgeInSeconds(60),
			},
			errorMsg: `fcors: option MaxAgeInSeconds used multiple times`,
		}, {
			desc: "option ExposeResponseHeaders used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("foo"),
				fcors.ExposeResponseHeaders("bar"),
			},
			errorMsg: `fcors: option ExposeResponseHeaders used multiple times`,
		}, {
			desc: "option ExposeAllResponseHeaders used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeAllResponseHeaders(),
				fcors.ExposeAllResponseHeaders(),
			},
			errorMsg: `fcors: option ExposeAllResponseHeaders used multiple times`,
		}, {
			desc: "option AssumeNoExtendedWildcardSupport used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.AssumeNoExtendedWildcardSupport(),
				risky.AssumeNoExtendedWildcardSupport(),
			},
			errorMsg: `fcors/risky: option AssumeNoExtendedWildcardSupport used multiple times`,
		}, {
			desc: "option PreflightSuccessStatus used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(201),
				fcors.PreflightSuccessStatus(202),
			},
			errorMsg: `fcors: option PreflightSuccessStatus used multiple times`,
		}, {
			desc: "option AssumeNoWebCachingOfPreflightResponses used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.AssumeNoWebCachingOfPreflightResponses(),
				risky.AssumeNoWebCachingOfPreflightResponses(),
			},
			errorMsg: `fcors/risky: option AssumeNoWebCachingOfPreflightResponses used multiple times`,
		}, {
			desc: "option LocalNetworkAccess used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccess(),
				risky.LocalNetworkAccess(),
			},
			errorMsg: `fcors/risky: option LocalNetworkAccess used multiple times`,
		}, {
			desc: "option LocalNetworkAccessInNoCorsModeOnly used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
			},
			errorMsg: `fcors/risky: option LocalNetworkAccessInNoCorsModeOnly used multiple times`,
		}, {
			desc: "option TolerateInsecureOrigins used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("http://example.com"),
				risky.TolerateInsecureOrigins(),
				risky.TolerateInsecureOrigins(),
			},
			errorMsg: `fcors/risky: option TolerateInsecureOrigins used multiple times`,
		}, {
			desc: "option SkipPublicSuffixCheck used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.SkipPublicSuffixCheck(),
				risky.SkipPublicSuffixCheck(),
			},
			errorMsg: `fcors/risky: option SkipPublicSuffixCheck used multiple times`,
		}, {
			desc: "conjunct use of options FromOrigins and FromAnyOrigin",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.FromAnyOrigin(),
			},
			errorMsg: `fcors: incompatible options FromOrigins and FromAnyOrigin`,
		}, {
			desc: "conjunct use of options WithMethods and WithAnyMethod",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: incompatible options WithMethods and WithAnyMethod`,
		}, {
			desc: "conjunct use of options WithRequestHeaders and WithAnyRequestHeaders",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Authorization"),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: incompatible options WithRequestHeaders and WithAnyRequestHeaders`,
		}, {
			desc: "conjunct use of options LocalNetworkAccess and LocalNetworkAccessInNoCorsModeOnly",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccess(),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
			},
			errorMsg: `fcors: incompatible options LocalNetworkAccess and LocalNetworkAccessInNoCorsModeOnly`,
		}, {
			desc: "conjunct use of options FromAnyOrigin and LocalNetworkAccess",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				risky.LocalNetworkAccess(),
			},
			errorMsg: `fcors: incompatible options FromAnyOrigin and LocalNetworkAccess`,
		}, {
			desc: "conjunct use of options FromAnyOrigin and LocalNetworkAccessInNoCorsModeOnly",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
			},
			errorMsg: `fcors: incompatible options FromAnyOrigin and LocalNetworkAccessInNoCorsModeOnly`,
		}, {
			desc: "conjunct use of options ExposeResponseHeaders and ExposeAllResponseHeaders",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("Location"),
				fcors.ExposeAllResponseHeaders(),
			},
			errorMsg: `fcors: incompatible options ExposeResponseHeaders and ExposeAllResponseHeaders`,
		}, {
			desc: "conjunct use of options ExposeAllResponseHeaders and AssumeNoExtendedWildcardSupport",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeAllResponseHeaders(),
				risky.AssumeNoExtendedWildcardSupport(),
			},
			errorMsg: `fcors: incompatible options ExposeAllResponseHeaders and AssumeNoExtendedWildcardSupport`,
		}, {
			desc: "preflight success status outside the 2xx range",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(300),
			},
			errorMsg: `fcors: specified status 300 outside the 2xx range`,
		}, {
			desc: "multiple configuration errors",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"http://example.com",
					"https://example.com/",
				),
				fcors.WithMethods(
					http.MethodConnect,
					"not a valid method",
				),
				fcors.WithMethods(http.MethodGet),
				fcors.WithRequestHeaders(
					"not a valid header",
					"Access-control-allow-origin",
				),
				fcors.WithRequestHeaders("Authorization"),
				fcors.MaxAgeInSeconds(86401),
				fcors.MaxAgeInSeconds(129),
			},
			errorMsg: strings.Join(
				[]string{
					`fcors: invalid origin pattern: "https://example.com/"`,
					`fcors: forbidden method name "CONNECT"`,
					`fcors: invalid method name "not a valid method"`,
					`fcors: option WithMethods used multiple times`,
					`fcors: invalid request-header name "not a valid header"`,
					`fcors: disallowed request-header name "access-control-allow-origin"`,
					`fcors: option WithRequestHeaders used multiple times`,
					`fcors: specified max-age value 86401 exceeds upper bound 86400`,
					`fcors: option MaxAgeInSeconds used multiple times`,
					`fcors: most origin patterns like "http://example.com" that use insecure scheme "http" are by default prohibited`,
				}, "\n"),
		},
	}
	for _, p := range policies {
		f := func(t *testing.T) {
			if len(p.options) == 0 {
				t.Skip("skipping test because zero options")
			}
			_, err := fcors.AllowAccess(p.options[0], p.options[1:]...)
			if err == nil {
				t.Errorf("got nil error; want error with message %q", p.errorMsg)
				return
			}
			if err.Error() != p.errorMsg {
				t.Errorf("got error with message\n\t%q\nwant error with message\n\t%q", err.Error(), p.errorMsg)
			}
		}
		t.Run(p.desc, f)
	}
}

// These tests are only meant as a sanity check, not as a license
// to depend on the precise wording of the various error messages.
func TestInvalidPoliciesForAllowAccessWithCredentials(t *testing.T) {
	policies := []struct {
		desc     string
		options  []fcors.OptionCred
		errorMsg string
	}{
		{
			desc:     "specified origin contains whitespace",
			options:  []fcors.OptionCred{fcors.FromOrigins(" http://example.com:6060 ")},
			errorMsg: `fcors: invalid or unsupported scheme: " http://example.com:6060 "`,
		}, {
			desc:    "specified origin is insecure",
			options: []fcors.OptionCred{fcors.FromOrigins("http://example.com:6060")},
			errorMsg: `fcors: most origin patterns like "http://example.com:6060" that use ` +
				`insecure scheme "http" are by default prohibited`,
		}, {
			desc:     "specified origin's host is an invalid IP address",
			options:  []fcors.OptionCred{fcors.FromOrigins("http://[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://[::1]1:6060"`,
		}, {
			desc:     "specified origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://[::1]:6060")},
			errorMsg: `fcors: scheme "https" incompatible with an IP address: "https://[::1]:6060"`,
		}, {
			desc:     "specified origin is the null origin",
			options:  []fcors.OptionCred{fcors.FromOrigins("null")},
			errorMsg: `fcors: unsupported "null" origin`,
		}, {
			desc:     "specified origin contains an invalid scheme",
			options:  []fcors.OptionCred{fcors.FromOrigins("httpsfoo://example.com:6060")},
			errorMsg: `fcors: invalid or unsupported scheme: "httpsfoo://example.com:6060"`,
		}, {
			desc:     "specified origin contains a userinfo",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://user:password@example.com:6060")},
			errorMsg: `fcors: invalid port pattern: "https://user:password@example.com:6060"`,
		}, {
			desc:     "specified origin contains a path",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:6060/foo")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060/foo"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:6060?")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060?"`,
		}, {
			desc:     "specified origin contains a querystring",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a fragment",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:6060#index")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:6060#index"`,
		}, {
			desc:     "specified origin contains an invalid port",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:66536")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:66536"`,
		}, {
			desc:     "specified origin contains a 5-digit port that starts with a nonzero digit",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:06060")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:06060"`,
		}, {
			desc:     "specified origin contains a colon but no port",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com:")},
			errorMsg: `fcors: invalid port pattern: "https://example.com:"`,
		}, {
			desc:     "specified origin's host contains two trailing full stops",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://example.com..")},
			errorMsg: `fcors: invalid origin pattern: "https://example.com.."`,
		}, {
			desc: "an origin is specified multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins(
					"https://example.com:6060",
					"https://example.com:6060",
				),
			},
			errorMsg: `fcors: origin pattern "https://example.com:6060" specified multiple times`,
		}, {
			desc:     "misplaced subdomain pattern",
			options:  []fcors.OptionCred{fcors.FromOrigins("http://foo.*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://foo.*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains whitespace",
			options:  []fcors.OptionCred{fcors.FromOrigins(" http://*.example.com:6060 ")},
			errorMsg: `fcors: invalid or unsupported scheme: " http://*.example.com:6060 "`,
		}, {
			desc:    "specified base origin is insecure",
			options: []fcors.OptionCred{fcors.FromOrigins("http://*.example.com:6060")},
			errorMsg: `fcors: most origin patterns like "http://*.example.com:6060" that use ` +
				`insecure scheme "http" are by default prohibited`,
		}, {
			desc:     "specified base origin's host is an invalid IP address",
			options:  []fcors.OptionCred{fcors.FromOrigins("http://*.[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://*.[::1]1:6060"`,
		}, {
			desc:     "specified base origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.[::1]:6060")},
			errorMsg: `fcors: invalid origin pattern: "https://*.[::1]:6060"`,
		}, {
			desc:     "specified base origin's host is an IP address",
			options:  []fcors.OptionCred{fcors.FromOrigins("http://*.127.0.0.1:6060")},
			errorMsg: `fcors: invalid origin pattern: "http://*.127.0.0.1:6060"`,
		}, {
			desc:     "specified base origin contains an invalid scheme",
			options:  []fcors.OptionCred{fcors.FromOrigins("httpsfoo://*.example.com:6060")},
			errorMsg: `fcors: invalid or unsupported scheme: "httpsfoo://*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a userinfo",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://user:password@*.example.com:6060")},
			errorMsg: `fcors: invalid port pattern: "https://user:password@*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a path",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:6060/foo")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060/foo"`,
		}, {
			desc:     "specified base origin contains a querystring",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:6060?")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060?"`,
		}, {
			desc:     "specified base origin contains a fragment",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:6060#index")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:6060#index"`,
		}, {
			desc:     "specified base origin contains an invalid port",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:66536")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:66536"`,
		}, {
			desc:     "specified base origin contains a colon but no port",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com:")},
			errorMsg: `fcors: invalid port pattern: "https://*.example.com:"`,
		}, {
			desc:     "specified base origin's host contains two trailing full stops",
			options:  []fcors.OptionCred{fcors.FromOrigins("https://*.example.com..")},
			errorMsg: `fcors: invalid origin pattern: "https://*.example.com.."`,
		}, {
			desc: "a base origin is specified multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins(
					"https://*.example.com:6060",
					"https://*.example.com:6060",
				),
			},
			errorMsg: `fcors: origin pattern "https://*.example.com:6060" specified multiple times`,
		}, {
			desc: "invalid second origin pattern",
			options: []fcors.OptionCred{
				fcors.FromOrigins(
					"https://example.com",
					"https://*.127.0.0.1:6060",
				),
			},
			errorMsg: `fcors: invalid origin pattern: "https://*.127.0.0.1:6060"`,
		}, {
			desc:    "specified base origin's host is a public suffix",
			options: []fcors.OptionCred{fcors.FromOrigins("https://*.github.io")},
			errorMsg: `fcors: origin patterns like "https://*.github.io" that allow arbitrary ` +
				`subdomains of public suffix "github.io" are by default prohibited`,
		}, {
			desc:     "missing call to FromOrigins",
			options:  []fcors.OptionCred{fcors.WithAnyMethod()},
			errorMsg: `fcors: missing call to FromOrigins in AllowAccessWithCredentials`,
		}, {
			desc: "empty method name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(""),
			},
			errorMsg: `fcors: invalid method name ""`,
		}, {
			desc: "illegal chars in method name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "wildcard method name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("*"),
			},
			errorMsg: `fcors: disallowed method name "*"`,
		}, {
			desc: "invalid second method name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("foo", "résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "empty request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders(""),
			},
			errorMsg: `fcors: invalid request-header name ""`,
		}, {
			desc: "illegal chars in request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "wildcard request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("*"),
			},
			errorMsg: `fcors: disallowed request-header name "*"`,
		}, {
			desc: "invalid second request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "forbidden request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("connection"),
			},
			errorMsg: `fcors: forbidden request-header name "connection"`,
		}, {
			desc: "forbidden request-header name Sec-Foo",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Sec-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "sec-foo"`,
		}, {
			desc: "forbidden request-header name Proxy-Foo",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Proxy-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "proxy-foo"`,
		}, {
			desc: "same request-header name specified multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Foo", "Foo"),
			},
			errorMsg: `fcors: request-header name "foo" specified multiple times`,
		}, {
			desc: "disallowed request-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("access-control-allow-origin"),
			},
			errorMsg: `fcors: disallowed request-header name "access-control-allow-origin"`,
		}, {
			desc: "max age exceeds upper bound",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.MaxAgeInSeconds(86401),
			},
			errorMsg: `fcors: specified max-age value 86401 exceeds upper bound 86400`,
		}, {
			desc: "empty response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders(""),
			},
			errorMsg: `fcors: invalid response-header name ""`,
		}, {
			desc: "illegal chars in response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: disallowed response-header name "*"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: disallowed response-header name "*"`,
		}, {
			desc: "invalid second response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "forbidden response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("set-cookie"),
			},
			errorMsg: `fcors: forbidden response-header name "set-cookie"`,
		}, {
			desc: "same response-header name specified multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("Foo", "Foo"),
			},
			errorMsg: `fcors: response-header name "foo" specified multiple times`,
		}, {
			desc: "disallowed response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("access-control-request-method"),
			},
			errorMsg: `fcors: disallowed response-header name "access-control-request-method"`,
		}, {
			desc: "safelisted response-header name",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("cache-control"),
			},
			errorMsg: `fcors: response-header name "cache-control" needs not be explicitly exposed`,
		}, {
			desc: "option FromOrigins used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.FromOrigins("https://example.co.uk"),
			},
			errorMsg: `fcors: option FromOrigins used multiple times`,
		}, {
			desc: "option WithMethods used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithMethods(http.MethodPost),
			},
			errorMsg: `fcors: option WithMethods used multiple times`,
		}, {
			desc: "option WithAnyMethod used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyMethod(),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: option WithAnyMethod used multiple times`,
		}, {
			desc: "option WithRequestHeaders used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("foo"),
				fcors.WithRequestHeaders("bar"),
			},
			errorMsg: `fcors: option WithRequestHeaders used multiple times`,
		}, {
			desc: "option WithAnyRequestHeaders used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyRequestHeaders(),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: option WithAnyRequestHeaders used multiple times`,
		}, {
			desc: "option MaxAgeInSeconds used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.MaxAgeInSeconds(30),
				fcors.MaxAgeInSeconds(60),
			},
			errorMsg: `fcors: option MaxAgeInSeconds used multiple times`,
		}, {
			desc: "option ExposeResponseHeaders used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("foo"),
				fcors.ExposeResponseHeaders("bar"),
			},
			errorMsg: `fcors: option ExposeResponseHeaders used multiple times`,
		}, {
			desc: "option PreflightSuccessStatus used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(201),
				fcors.PreflightSuccessStatus(202),
			},
			errorMsg: `fcors: option PreflightSuccessStatus used multiple times`,
		}, {
			desc: "option AssumeNoWebCachingOfPreflightResponses used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				risky.AssumeNoWebCachingOfPreflightResponses(),
				risky.AssumeNoWebCachingOfPreflightResponses(),
			},
			errorMsg: `fcors/risky: option AssumeNoWebCachingOfPreflightResponses used multiple times`,
		}, {
			desc: "option LocalNetworkAccess used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccess(),
				risky.LocalNetworkAccess(),
			},
			errorMsg: `fcors/risky: option LocalNetworkAccess used multiple times`,
		}, {
			desc: "option LocalNetworkAccessInNoCorsModeOnly used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
			},
			errorMsg: `fcors/risky: option LocalNetworkAccessInNoCorsModeOnly used multiple times`,
		}, {
			desc: "option TolerateInsecureOrigins used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("http://example.com"),
				risky.TolerateInsecureOrigins(),
				risky.TolerateInsecureOrigins(),
			},
			errorMsg: `fcors/risky: option TolerateInsecureOrigins used multiple times`,
		}, {
			desc: "option SkipPublicSuffixCheck used multiple times",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				risky.SkipPublicSuffixCheck(),
				risky.SkipPublicSuffixCheck(),
			},
			errorMsg: `fcors/risky: option SkipPublicSuffixCheck used multiple times`,
		}, {
			desc: "conjunct use of options WithMethods and WithAnyMethod",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: incompatible options WithMethods and WithAnyMethod`,
		}, {
			desc: "conjunct use of options WithRequestHeaders and WithAnyRequestHeaders",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Authorization"),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: incompatible options WithRequestHeaders and WithAnyRequestHeaders`,
		}, {
			desc: "conjunct use of options LocalNetworkAccess and LocalNetworkAccessInNoCorsModeOnly",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				risky.LocalNetworkAccess(),
				risky.LocalNetworkAccessInNoCorsModeOnly(),
			},
			errorMsg: `fcors: incompatible options LocalNetworkAccess and LocalNetworkAccessInNoCorsModeOnly`,
		}, {
			desc: "preflight success status outside the 2xx range",
			options: []fcors.OptionCred{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(300),
			},
			errorMsg: `fcors: specified status 300 outside the 2xx range`,
		}, {
			desc: "multiple configuration errors",
			options: []fcors.OptionCred{
				fcors.FromOrigins(
					"http://example.com",
					"https://example.com/",
				),
				fcors.WithMethods(
					http.MethodConnect,
					"not a valid method",
				),
				fcors.WithMethods(http.MethodGet),
				fcors.WithRequestHeaders(
					"not a valid header",
					"Access-control-allow-origin",
				),
				fcors.WithRequestHeaders("Authorization"),
				fcors.MaxAgeInSeconds(86401),
				fcors.MaxAgeInSeconds(129),
			},
			errorMsg: strings.Join(
				[]string{
					`fcors: invalid origin pattern: "https://example.com/"`,
					`fcors: forbidden method name "CONNECT"`,
					`fcors: invalid method name "not a valid method"`,
					`fcors: option WithMethods used multiple times`,
					`fcors: invalid request-header name "not a valid header"`,
					`fcors: disallowed request-header name "access-control-allow-origin"`,
					`fcors: option WithRequestHeaders used multiple times`,
					`fcors: specified max-age value 86401 exceeds upper bound 86400`,
					`fcors: option MaxAgeInSeconds used multiple times`,
					`fcors: most origin patterns like "http://example.com" that use insecure scheme "http" are by default prohibited`,
				}, "\n"),
		},
	}
	for _, p := range policies {
		f := func(t *testing.T) {
			if len(p.options) == 0 {
				t.Skip("skipping test because zero options")
			}
			_, err := fcors.AllowAccessWithCredentials(p.options[0], p.options[1:]...)
			if err == nil {
				t.Errorf("got nil error; want error with message %q", p.errorMsg)
				return
			}
			if err.Error() != p.errorMsg {
				t.Errorf("got error with message\n\t%q\nwant error with message\n\t%q", err.Error(), p.errorMsg)
			}
		}
		t.Run(p.desc, f)
	}
}
