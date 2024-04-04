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
			errorMsg: `fcors: invalid origin pattern " http://example.com:6060 "`,
		}, {
			desc: "option PrivateNetworkAccess is used and specified origin is insecure",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("http://example.com:6060"),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060" ` +
				`are by default prohibited when Private-Network Access is enabled`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly is used and specified origin is insecure",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("http://example.com:6060"),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060" ` +
				`are by default prohibited when Private-Network Access is enabled`,
		}, {
			desc:     "specified origin's host is an invalid IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://[::1]1:6060"`,
		}, {
			desc:     "specified origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://[::1]:6060")},
			errorMsg: `fcors: scheme "https" incompatible with an IP address: "https://[::1]:6060"`,
		}, {
			desc:     "specified origin is the null origin",
			options:  []fcors.OptionAnon{fcors.FromOrigins("null")},
			errorMsg: `fcors: prohibited origin "null"`,
		}, {
			desc:     "specified origin contains an invalid scheme",
			options:  []fcors.OptionAnon{fcors.FromOrigins("httpsfoo://example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "httpsfoo://example.com:6060"`,
		}, {
			desc:     "specified origin contains a userinfo",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://user:password@example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "https://user:password@example.com:6060"`,
		}, {
			desc:     "specified origin contains a path",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060/foo")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060/foo"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060?")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060?"`,
		}, {
			desc:     "specified origin contains a querystring",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a fragment",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:6060#index")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060#index"`,
		}, {
			desc:     "specified origin contains an invalid port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:66536")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:66536"`,
		}, {
			desc:     "specified origin contains a 5-digit port that starts with a nonzero digit",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:06060")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:06060"`,
		}, {
			desc:     "specified origin contains a colon but no port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com:")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:"`,
		}, {
			desc:     "specified origin's host contains two trailing full stops",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://example.com..")},
			errorMsg: `fcors: invalid origin pattern "https://example.com.."`,
		}, {
			desc:     "misplaced subdomain pattern",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://foo.*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "http://foo.*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains whitespace",
			options:  []fcors.OptionAnon{fcors.FromOrigins(" http://*.example.com:6060 ")},
			errorMsg: `fcors: invalid origin pattern " http://*.example.com:6060 "`,
		}, {
			desc: "option PrivateNetworkAccess is used and some origin patterns are insecure",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"http://example.com:6060",
					"http://*.example.com:6060",
				),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060", "http://*.example.com:6060" ` +
				`are by default prohibited when Private-Network Access is enabled`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly is used and some origin patterns are insecure",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"http://example.com:6060",
					"http://*.example.com:6060",
				),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060", "http://*.example.com:6060" ` +
				`are by default prohibited when Private-Network Access is enabled`,
		}, {
			desc:     "specified base origin's host is an invalid IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://*.[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://*.[::1]1:6060"`,
		}, {
			desc:     "specified base origin's scheme is https but its host is an IP address ",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.[::1]:6060")},
			errorMsg: `fcors: invalid origin pattern "https://*.[::1]:6060"`,
		}, {
			desc:     "specified base origin's host is an IP address",
			options:  []fcors.OptionAnon{fcors.FromOrigins("http://*.127.0.0.1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://*.127.0.0.1:6060"`,
		}, {
			desc:     "specified base origin contains an invalid scheme",
			options:  []fcors.OptionAnon{fcors.FromOrigins("httpsfoo://*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "httpsfoo://*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a userinfo",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://user:password@*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "https://user:password@*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a path",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060/foo")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060/foo"`,
		}, {
			desc:     "specified base origin contains a querystring",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060?")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060?"`,
		}, {
			desc:     "specified base origin contains a fragment",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:6060#index")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060#index"`,
		}, {
			desc:     "specified base origin contains an invalid port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:66536")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:66536"`,
		}, {
			desc:     "specified base origin contains a colon but no port",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com:")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:"`,
		}, {
			desc:     "specified base origin's host contains two trailing full stops",
			options:  []fcors.OptionAnon{fcors.FromOrigins("https://*.example.com..")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com.."`,
		}, {
			desc: "invalid second origin pattern",
			options: []fcors.OptionAnon{
				fcors.FromOrigins(
					"https://example.com",
					"https://*.127.0.0.1:6060",
				),
			},
			errorMsg: `fcors: invalid origin pattern "https://*.127.0.0.1:6060"`,
		}, {
			desc:    "specified base origin's host is a public suffix",
			options: []fcors.OptionAnon{fcors.FromOrigins("https://*.github.io")},
			errorMsg: `fcors: origin patterns like "https://*.github.io" that encompass ` +
				`subdomains of a public suffix are by default prohibited`,
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
			desc: "wildcard origin",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("*"),
			},
			errorMsg: `fcors: prohibited origin "*"`,
		}, {
			desc: "wildcard method name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithMethods("*"),
			},
			errorMsg: `fcors: prohibited method name "*"`,
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
			errorMsg: `fcors: prohibited request-header name "*"`,
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
			desc: "prohibited request-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.WithRequestHeaders("access-control-allow-origin"),
			},
			errorMsg: `fcors: prohibited request-header name "access-control-allow-origin"`,
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
			errorMsg: `fcors: prohibited response-header name "*"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: prohibited response-header name "*"`,
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
			desc: "prohibited response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("access-control-request-method"),
			},
			errorMsg: `fcors: prohibited response-header name "access-control-request-method"`,
		}, {
			desc: "prohibited preflight response-header name",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				fcors.ExposeResponseHeaders("access-control-max-age"),
			},
			errorMsg: `fcors: prohibited response-header name "access-control-max-age"`,
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
			desc: "option PreflightSuccessStatus used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(201),
				fcors.PreflightSuccessStatus(202),
			},
			errorMsg: `fcors: option PreflightSuccessStatus used multiple times`,
		}, {
			desc: "option PrivateNetworkAccess used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccess(),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors/risky: option PrivateNetworkAccess used multiple times`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly used multiple times",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors/risky: option PrivateNetworkAccessInNoCORSModeOnly used multiple times`,
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
			desc: "conjunct use of options PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccess(),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: incompatible options PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly`,
		}, {
			desc: "conjunct use of options FromAnyOrigin and PrivateNetworkAccess",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors: incompatible options FromAnyOrigin and PrivateNetworkAccess`,
		}, {
			desc: "conjunct use of options FromAnyOrigin and PrivateNetworkAccessInNoCORSModeOnly",
			options: []fcors.OptionAnon{
				fcors.FromAnyOrigin(),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: incompatible options FromAnyOrigin and PrivateNetworkAccessInNoCORSModeOnly`,
		}, {
			desc: "conjunct use of options ExposeResponseHeaders and ExposeAllResponseHeaders",
			options: []fcors.OptionAnon{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("Location"),
				fcors.ExposeAllResponseHeaders(),
			},
			errorMsg: `fcors: incompatible options ExposeResponseHeaders and ExposeAllResponseHeaders`,
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
					`fcors: invalid origin pattern "https://example.com/"`,
					`fcors: forbidden method name "CONNECT"`,
					`fcors: invalid method name "not a valid method"`,
					`fcors: option WithMethods used multiple times`,
					`fcors: invalid request-header name "not a valid header"`,
					`fcors: prohibited request-header name "access-control-allow-origin"`,
					`fcors: option WithRequestHeaders used multiple times`,
					`fcors: specified max-age value 86401 exceeds upper bound 86400`,
					`fcors: option MaxAgeInSeconds used multiple times`,
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
		options  []fcors.Option
		errorMsg string
	}{
		{
			desc:     "specified origin contains whitespace",
			options:  []fcors.Option{fcors.FromOrigins(" http://example.com:6060 ")},
			errorMsg: `fcors: invalid origin pattern " http://example.com:6060 "`,
		}, {
			desc:    "specified origin is insecure",
			options: []fcors.Option{fcors.FromOrigins("http://example.com:6060")},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled`,
		}, {
			desc: "option PrivateNetworkAccess is used and specified origin is insecure",
			options: []fcors.Option{
				fcors.FromOrigins("http://example.com:6060"),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled and/or ` +
				`Private-Network Access is enabled`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly is used and specified origin is insecure",
			options: []fcors.Option{
				fcors.FromOrigins("http://example.com:6060"),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled and/or ` +
				`Private-Network Access is enabled`,
		}, {
			desc:     "specified origin's host is an invalid IP address",
			options:  []fcors.Option{fcors.FromOrigins("http://[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://[::1]1:6060"`,
		}, {
			desc:     "specified origin's scheme is https but its host is an IP address ",
			options:  []fcors.Option{fcors.FromOrigins("https://[::1]:6060")},
			errorMsg: `fcors: scheme "https" incompatible with an IP address: "https://[::1]:6060"`,
		}, {
			desc:     "specified origin is the null origin",
			options:  []fcors.Option{fcors.FromOrigins("null")},
			errorMsg: `fcors: prohibited origin "null"`,
		}, {
			desc:     "specified origin contains an invalid scheme",
			options:  []fcors.Option{fcors.FromOrigins("httpsfoo://example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "httpsfoo://example.com:6060"`,
		}, {
			desc:     "specified origin contains a userinfo",
			options:  []fcors.Option{fcors.FromOrigins("https://user:password@example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "https://user:password@example.com:6060"`,
		}, {
			desc:     "specified origin contains a path",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:6060/foo")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060/foo"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:6060?")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060?"`,
		}, {
			desc:     "specified origin contains a querystring",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a fragment",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:6060#index")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:6060#index"`,
		}, {
			desc:     "specified origin contains an invalid port",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:66536")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:66536"`,
		}, {
			desc:     "specified origin contains a 5-digit port that starts with a nonzero digit",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:06060")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:06060"`,
		}, {
			desc:     "specified origin contains a colon but no port",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com:")},
			errorMsg: `fcors: invalid origin pattern "https://example.com:"`,
		}, {
			desc:     "specified origin's host contains two trailing full stops",
			options:  []fcors.Option{fcors.FromOrigins("https://example.com..")},
			errorMsg: `fcors: invalid origin pattern "https://example.com.."`,
		}, {
			desc:     "misplaced subdomain pattern",
			options:  []fcors.Option{fcors.FromOrigins("http://foo.*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "http://foo.*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains whitespace",
			options:  []fcors.Option{fcors.FromOrigins(" http://*.example.com:6060 ")},
			errorMsg: `fcors: invalid origin pattern " http://*.example.com:6060 "`,
		}, {
			desc:    "specified base origin is insecure",
			options: []fcors.Option{fcors.FromOrigins("http://*.example.com:6060")},
			errorMsg: `fcors: insecure origin patterns like "http://*.example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled`,
		}, {
			desc: "option PrivateNetworkAccess is used and some origin patterns are insecure",
			options: []fcors.Option{
				fcors.FromOrigins(
					"http://example.com:6060",
					"http://*.example.com:6060",
				),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060", "http://*.example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled and/or ` +
				`Private-Network Access is enabled`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly is used and some origin patterns are insecure",
			options: []fcors.Option{
				fcors.FromOrigins(
					"http://example.com:6060",
					"http://*.example.com:6060",
				),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: insecure origin patterns like "http://example.com:6060", "http://*.example.com:6060" ` +
				`are by default prohibited when credentialed access is enabled and/or ` +
				`Private-Network Access is enabled`,
		}, {
			desc:     "specified base origin's host is an invalid IP address",
			options:  []fcors.Option{fcors.FromOrigins("http://*.[::1]1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://*.[::1]1:6060"`,
		}, {
			desc:     "specified base origin's scheme is https but its host is an IP address ",
			options:  []fcors.Option{fcors.FromOrigins("https://*.[::1]:6060")},
			errorMsg: `fcors: invalid origin pattern "https://*.[::1]:6060"`,
		}, {
			desc:     "specified base origin's host is an IP address",
			options:  []fcors.Option{fcors.FromOrigins("http://*.127.0.0.1:6060")},
			errorMsg: `fcors: invalid origin pattern "http://*.127.0.0.1:6060"`,
		}, {
			desc:     "specified base origin contains an invalid scheme",
			options:  []fcors.Option{fcors.FromOrigins("httpsfoo://*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "httpsfoo://*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a userinfo",
			options:  []fcors.Option{fcors.FromOrigins("https://user:password@*.example.com:6060")},
			errorMsg: `fcors: invalid origin pattern "https://user:password@*.example.com:6060"`,
		}, {
			desc:     "specified base origin contains a path",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:6060/foo")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060/foo"`,
		}, {
			desc:     "specified base origin contains a querystring",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:6060?foo=bar")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060?foo=bar"`,
		}, {
			desc:     "specified origin contains a querystring delimiter",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:6060?")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060?"`,
		}, {
			desc:     "specified base origin contains a fragment",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:6060#index")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:6060#index"`,
		}, {
			desc:     "specified base origin contains an invalid port",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:66536")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:66536"`,
		}, {
			desc:     "specified base origin contains a colon but no port",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com:")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com:"`,
		}, {
			desc:     "specified base origin's host contains two trailing full stops",
			options:  []fcors.Option{fcors.FromOrigins("https://*.example.com..")},
			errorMsg: `fcors: invalid origin pattern "https://*.example.com.."`,
		}, {
			desc: "invalid second origin pattern",
			options: []fcors.Option{
				fcors.FromOrigins(
					"https://example.com",
					"https://*.127.0.0.1:6060",
				),
			},
			errorMsg: `fcors: invalid origin pattern "https://*.127.0.0.1:6060"`,
		}, {
			desc:    "specified base origin's host is a public suffix",
			options: []fcors.Option{fcors.FromOrigins("https://*.github.io")},
			errorMsg: `fcors: origin patterns like "https://*.github.io" that encompass ` +
				`subdomains of a public suffix are by default prohibited`,
		}, {
			desc:     "missing call to FromOrigins",
			options:  []fcors.Option{fcors.WithAnyMethod()},
			errorMsg: `fcors: missing call to FromOrigins in AllowAccessWithCredentials`,
		}, {
			desc: "empty method name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(""),
			},
			errorMsg: `fcors: invalid method name ""`,
		}, {
			desc: "illegal chars in method name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "wildcard method name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("*"),
			},
			errorMsg: `fcors: prohibited method name "*"`,
		}, {
			desc: "invalid second method name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods("foo", "résumé"),
			},
			errorMsg: `fcors: invalid method name "résumé"`,
		}, {
			desc: "empty request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders(""),
			},
			errorMsg: `fcors: invalid request-header name ""`,
		}, {
			desc: "illegal chars in request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "wildcard request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("*"),
			},
			errorMsg: `fcors: prohibited request-header name "*"`,
		}, {
			desc: "invalid second request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid request-header name "résumé"`,
		}, {
			desc: "forbidden request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("connection"),
			},
			errorMsg: `fcors: forbidden request-header name "connection"`,
		}, {
			desc: "forbidden request-header name Sec-Foo",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Sec-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "sec-foo"`,
		}, {
			desc: "forbidden request-header name Proxy-Foo",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Proxy-Foo"),
			},
			errorMsg: `fcors: forbidden request-header name "proxy-foo"`,
		}, {
			desc: "prohibited request-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("access-control-allow-origin"),
			},
			errorMsg: `fcors: prohibited request-header name "access-control-allow-origin"`,
		}, {
			desc: "max age exceeds upper bound",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.MaxAgeInSeconds(86401),
			},
			errorMsg: `fcors: specified max-age value 86401 exceeds upper bound 86400`,
		}, {
			desc: "empty response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders(""),
			},
			errorMsg: `fcors: invalid response-header name ""`,
		}, {
			desc: "illegal chars in response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: prohibited response-header name "*"`,
		}, {
			desc: "wildcard response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("*"),
			},
			errorMsg: `fcors: prohibited response-header name "*"`,
		}, {
			desc: "invalid second response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("foo", "résumé"),
			},
			errorMsg: `fcors: invalid response-header name "résumé"`,
		}, {
			desc: "forbidden response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("set-cookie"),
			},
			errorMsg: `fcors: forbidden response-header name "set-cookie"`,
		}, {
			desc: "prohibited response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("access-control-request-method"),
			},
			errorMsg: `fcors: prohibited response-header name "access-control-request-method"`,
		}, {
			desc: "prohibited preflight response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("access-control-max-age"),
			},
			errorMsg: `fcors: prohibited response-header name "access-control-max-age"`,
		}, {
			desc: "safelisted response-header name",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("cache-control"),
			},
			errorMsg: `fcors: response-header name "cache-control" needs not be explicitly exposed`,
		}, {
			desc: "option FromOrigins used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.FromOrigins("https://example.co.uk"),
			},
			errorMsg: `fcors: option FromOrigins used multiple times`,
		}, {
			desc: "option WithMethods used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithMethods(http.MethodPost),
			},
			errorMsg: `fcors: option WithMethods used multiple times`,
		}, {
			desc: "option WithAnyMethod used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyMethod(),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: option WithAnyMethod used multiple times`,
		}, {
			desc: "option WithRequestHeaders used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("foo"),
				fcors.WithRequestHeaders("bar"),
			},
			errorMsg: `fcors: option WithRequestHeaders used multiple times`,
		}, {
			desc: "option WithAnyRequestHeaders used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithAnyRequestHeaders(),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: option WithAnyRequestHeaders used multiple times`,
		}, {
			desc: "option MaxAgeInSeconds used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.MaxAgeInSeconds(30),
				fcors.MaxAgeInSeconds(60),
			},
			errorMsg: `fcors: option MaxAgeInSeconds used multiple times`,
		}, {
			desc: "option ExposeResponseHeaders used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.ExposeResponseHeaders("foo"),
				fcors.ExposeResponseHeaders("bar"),
			},
			errorMsg: `fcors: option ExposeResponseHeaders used multiple times`,
		}, {
			desc: "option PreflightSuccessStatus used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(201),
				fcors.PreflightSuccessStatus(202),
			},
			errorMsg: `fcors: option PreflightSuccessStatus used multiple times`,
		}, {
			desc: "option PrivateNetworkAccess used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccess(),
				risky.PrivateNetworkAccess(),
			},
			errorMsg: `fcors/risky: option PrivateNetworkAccess used multiple times`,
		}, {
			desc: "option PrivateNetworkAccessInNoCORSModeOnly used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors/risky: option PrivateNetworkAccessInNoCORSModeOnly used multiple times`,
		}, {
			desc: "option TolerateInsecureOrigins used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("http://example.com"),
				risky.TolerateInsecureOrigins(),
				risky.TolerateInsecureOrigins(),
			},
			errorMsg: `fcors/risky: option TolerateInsecureOrigins used multiple times`,
		}, {
			desc: "option SkipPublicSuffixCheck used multiple times",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				risky.SkipPublicSuffixCheck(),
				risky.SkipPublicSuffixCheck(),
			},
			errorMsg: `fcors/risky: option SkipPublicSuffixCheck used multiple times`,
		}, {
			desc: "conjunct use of options WithMethods and WithAnyMethod",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithMethods(http.MethodGet),
				fcors.WithAnyMethod(),
			},
			errorMsg: `fcors: incompatible options WithMethods and WithAnyMethod`,
		}, {
			desc: "conjunct use of options WithRequestHeaders and WithAnyRequestHeaders",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.WithRequestHeaders("Authorization"),
				fcors.WithAnyRequestHeaders(),
			},
			errorMsg: `fcors: incompatible options WithRequestHeaders and WithAnyRequestHeaders`,
		}, {
			desc: "conjunct use of options PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				risky.PrivateNetworkAccess(),
				risky.PrivateNetworkAccessInNoCORSModeOnly(),
			},
			errorMsg: `fcors: incompatible options PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly`,
		}, {
			desc: "preflight success status outside the 2xx range",
			options: []fcors.Option{
				fcors.FromOrigins("https://example.com"),
				fcors.PreflightSuccessStatus(300),
			},
			errorMsg: `fcors: specified status 300 outside the 2xx range`,
		}, {
			desc: "multiple configuration errors",
			options: []fcors.Option{
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
					`fcors: invalid origin pattern "https://example.com/"`,
					`fcors: forbidden method name "CONNECT"`,
					`fcors: invalid method name "not a valid method"`,
					`fcors: option WithMethods used multiple times`,
					`fcors: invalid request-header name "not a valid header"`,
					`fcors: prohibited request-header name "access-control-allow-origin"`,
					`fcors: option WithRequestHeaders used multiple times`,
					`fcors: specified max-age value 86401 exceeds upper bound 86400`,
					`fcors: option MaxAgeInSeconds used multiple times`,
					`fcors: insecure origin patterns like "http://example.com" ` +
						`are by default prohibited when credentialed access is enabled`,
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
