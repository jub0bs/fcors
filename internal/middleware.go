package internal

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jub0bs/fcors/internal/origin"
	"github.com/jub0bs/fcors/internal/util"
)

const (
	headerOrigin = "Origin"

	headerRequestMethod         = "Access-Control-Request-Method"
	headerRequestHeaders        = "Access-Control-Request-Headers"
	headerRequestPrivateNetwork = "Access-Control-Request-Private-Network"

	headerAllowMethods        = "Access-Control-Allow-Methods"
	headerAllowHeaders        = "Access-Control-Allow-Headers"
	headerMageAge             = "Access-Control-Max-Age"
	headerAllowPrivateNetwork = "Access-Control-Allow-Private-Network"

	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowCredentials = "Access-Control-Allow-Credentials"

	headerExposeHeaders = "Access-Control-Expose-Headers"

	headerVary          = "Vary"
	headerAuthorization = "Authorization"
	headerValueTrue     = "true"

	wildcard = "*"
	comma    = ','
)

var (
	// effective constants (precomputed as a micro-optimization)
	precomputedPreflightVaryValue []string
	precomputedTrue               = []string{headerValueTrue}
	precomputedHeaderOrigin       = []string{headerOrigin}
)

type Middleware = func(http.Handler) http.Handler

func init() {
	const commaSpace = ", "
	var b strings.Builder
	b.WriteString(headerRequestHeaders)
	b.WriteString(commaSpace)
	b.WriteString(headerRequestMethod)
	b.WriteString(commaSpace)
	b.WriteString(headerRequestPrivateNetwork)
	b.WriteString(commaSpace)
	b.WriteString(headerOrigin)
	precomputedPreflightVaryValue = []string{b.String()}
}

type TempConfig struct {
	PublicSuffixes                                []string
	InsecureOriginPatterns                        []string
	SingleNonWildcardOrigin                       string
	AllowedMethods                                util.Set[string]
	AllowedRequestHeaders                         util.Set[string]
	CustomPreflightSuccessStatus                  bool
	DangerouslyTolerateSubdomainsOfPublicSuffixes bool
	DangerouslyTolerateInsecureOrigins            bool
	FromOriginsCalled                             bool
	WithMethodsCalled                             bool
	WithRequestHeadersCalled                      bool
	MaxAgeInSecondsCalled                         bool
	ExposeResponseHeadersCalled                   bool
}

type Config struct {
	// A nil ACAO indicates that the corresponding header
	// is set dynamically.
	ACAO                                 []string
	ACAM                                 []string
	Corpus                               origin.Corpus
	tmp                                  *TempConfig
	ACAH                                 []string
	ACMA                                 []string
	PreflightSuccessStatus               int
	AllowAnyMethod                       bool
	AllowAnyRequestHeaders               bool
	AllowAnyOrigin                       bool
	AllowCredentials                     bool
	ExposeAllResponseHeaders             bool
	PrivateNetworkAccess                 bool
	PrivateNetworkAccessInNoCORSModeOnly bool
	ACEH                                 []string
	//lint:ignore U1000 because we pad to the end of the 3rd cache line
	_padding40 [40]bool
}

func newConfig(creds bool) *Config {
	config := Config{
		tmp:                    new(TempConfig),
		AllowCredentials:       creds,
		PreflightSuccessStatus: http.StatusNoContent,
	}
	return &config
}

func (cfg *Config) validate() error {
	var errs []error
	if len(cfg.tmp.InsecureOriginPatterns) > 0 &&
		(cfg.AllowCredentials || cfg.PrivateNetworkAccess || cfg.PrivateNetworkAccessInNoCORSModeOnly) &&
		!cfg.tmp.DangerouslyTolerateInsecureOrigins {
		// Note: We don't require risky.DangerouslyTolerateInsecureOrigins
		// when users specify one or more insecure origin patterns
		// in anonymous-only mode and without PNA;
		// in such cases, insecure origins like http://example.com
		// are indeed no less insecure than * is,
		// which itself doesn't require risky.DangerouslyTolerateInsecureOrigins.
		var errorMsg strings.Builder
		var patterns = cfg.tmp.InsecureOriginPatterns
		errorMsg.WriteString(`insecure origin patterns like "`)
		errorMsg.WriteString(strings.Join(patterns, `", "`))
		errorMsg.WriteString(`" are by default prohibited when `)
		if cfg.AllowCredentials {
			errorMsg.WriteString("credentialed access is enabled")
		}
		if cfg.PrivateNetworkAccess || cfg.PrivateNetworkAccessInNoCORSModeOnly {
			if cfg.AllowCredentials {
				errorMsg.WriteString(" and/or ")
			}
			errorMsg.WriteString("Private-Network Access is enabled")
		}
		err := util.NewError(errorMsg.String())
		errs = append(errs, err)
	}
	if len(cfg.tmp.PublicSuffixes) > 0 && !cfg.tmp.DangerouslyTolerateSubdomainsOfPublicSuffixes {
		var errorMsg strings.Builder
		errorMsg.WriteString(`origin patterns like "`)
		errorMsg.WriteString(strings.Join(cfg.tmp.PublicSuffixes, `", "`))
		errorMsg.WriteString(`" that encompass subdomains of a public suffix`)
		errorMsg.WriteString(" are by default prohibited")
		err := util.NewError(errorMsg.String())
		errs = append(errs, err)
	}
	if cfg.tmp.FromOriginsCalled && cfg.AllowAnyOrigin {
		const msg = "incompatible options " + optFO + " and " + optFAO
		errs = append(errs, util.NewError(msg))
	}
	if !cfg.AllowAnyOrigin && !cfg.tmp.FromOriginsCalled {
		if cfg.AllowCredentials {
			const msg = "missing call to " + optFO + " in AllowAccessWithCredentials"
			errs = append(errs, util.NewError(msg))
		} else {
			const msg = "missing call to " + optFO + " or " + optFAO + " in AllowAccess"
			errs = append(errs, util.NewError(msg))
		}
	}
	if cfg.tmp.WithMethodsCalled && cfg.AllowAnyMethod {
		const msg = "incompatible options " + optWM + " and " + optWAM
		errs = append(errs, util.NewError(msg))
	}
	if cfg.tmp.WithRequestHeadersCalled && cfg.AllowAnyRequestHeaders {
		const msg = "incompatible options " + optWRH + " and " + optWARH
		errs = append(errs, util.NewError(msg))
	}
	if cfg.PrivateNetworkAccess && cfg.PrivateNetworkAccessInNoCORSModeOnly {
		const msg = "incompatible options " + optPNA + " and " + optPNANC
		errs = append(errs, util.NewError(msg))
	}
	if cfg.AllowAnyOrigin && cfg.PrivateNetworkAccess {
		// see note in
		// https://developer.chrome.com/blog/private-network-access-preflight/#no-cors-mode
		const msg = "incompatible options " + optFAO + " and " + optPNA
		errs = append(errs, util.NewError(msg))
	}
	if cfg.AllowAnyOrigin && cfg.PrivateNetworkAccessInNoCORSModeOnly {
		// see note in
		// https://developer.chrome.com/blog/private-network-access-preflight/#no-cors-mode
		const msg = "incompatible options " + optFAO + " and " + optPNANC
		errs = append(errs, util.NewError(msg))
	}
	if cfg.tmp.ExposeResponseHeadersCalled && cfg.ExposeAllResponseHeaders {
		const msg = "incompatible options " + optERH + " and " + optEARH
		errs = append(errs, util.NewError(msg))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (cfg *Config) precomputeStuff() {
	precomputedWildcard := []string{wildcard}
	// precompute ACAO if it can be static
	switch {
	case !cfg.AllowCredentials && cfg.AllowAnyOrigin:
		cfg.ACAO = precomputedWildcard
	case cfg.tmp.SingleNonWildcardOrigin != "":
		cfg.ACAO = []string{cfg.tmp.SingleNonWildcardOrigin}
	}

	// precompute ACAM if it can be static
	switch {
	case !cfg.AllowCredentials && cfg.AllowAnyMethod:
		cfg.ACAM = precomputedWildcard
	case len(cfg.tmp.AllowedMethods) != 0:
		acam := sortCombineWithComma(cfg.tmp.AllowedMethods)
		cfg.ACAM = []string{acam}
	}

	// precompute ACAH if it can be static
	switch {
	case !cfg.AllowCredentials && cfg.AllowAnyRequestHeaders:
		var b strings.Builder
		b.WriteString(wildcard)
		b.WriteByte(comma)
		b.WriteString(byteLowercase(headerAuthorization))
		cfg.ACAH = []string{b.String()}
	case len(cfg.tmp.AllowedRequestHeaders) != 0:
		acah := sortCombineWithComma(cfg.tmp.AllowedRequestHeaders)
		cfg.ACAH = []string{acah}
	}

	// possibly overwrite precomputed ACEH (can always be static)
	if !cfg.AllowCredentials && cfg.ExposeAllResponseHeaders {
		cfg.ACEH = precomputedWildcard
	}
	cfg.tmp = nil // no longer needed; let's make it eligible to GC
}

func (cfg *Config) middleware() Middleware {
	middleware := func(h http.Handler) http.Handler {
		f := func(w http.ResponseWriter, r *http.Request) {
			isOptionsReq := r.Method == http.MethodOptions
			origins, found := first(r.Header, headerOrigin)
			if !found {
				// r is _not_ a CORS request.
				cfg.handleNonCORSRequest(w.Header(), isOptionsReq)
				h.ServeHTTP(w, r)
				return
			}
			// r is a CORS request (and possibly a CORS-preflight request);
			// see https://fetch.spec.whatwg.org/#cors-request.
			if !isOptionsReq {
				// r is a non-OPTIONS CORS request.
				cfg.handleNonPreflightCORSRequest(w, origins, isOptionsReq)
				h.ServeHTTP(w, r)
				return
			}
			acrm, found := first(r.Header, headerRequestMethod)
			if found {
				// r is a CORS-preflight request;
				// see https://fetch.spec.whatwg.org/#cors-preflight-request.
				cfg.handleCORSPreflightRequest(w, r.Header, origins, acrm)
				return
			}
			// r is a non-preflight OPTIONS CORS request.
			cfg.handleNonPreflightCORSRequest(w, origins, isOptionsReq)
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(f)
	}
	return middleware
}

func (cfg *Config) handleNonCORSRequest(respHeaders http.Header, isOptionsReq bool) {
	// see https://wicg.github.io/private-network-access/#shortlinks
	if cfg.PrivateNetworkAccessInNoCORSModeOnly {
		if isOptionsReq {
			fastAdd(respHeaders, headerVary, precomputedPreflightVaryValue)
		}
		return
	}
	var varyHeaderAdded bool
	if isOptionsReq {
		fastAdd(respHeaders, headerVary, precomputedPreflightVaryValue)
		varyHeaderAdded = true
	}
	if cfg.ACAO == nil {
		if !varyHeaderAdded {
			fastAdd(respHeaders, headerVary, precomputedHeaderOrigin)
		}
		return
	}
	// See the last paragraph in
	// https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
	respHeaders[headerAllowOrigin] = cfg.ACAO
	if cfg.AllowCredentials {
		// See https://github.com/whatwg/fetch/issues/1601.
		// We make no attempt to infer whether the request is credentialed.
		respHeaders[headerAllowCredentials] = precomputedTrue
	}
	if cfg.ACEH != nil {
		// Similar to https://github.com/whatwg/fetch/issues/1601.
		respHeaders[headerExposeHeaders] = cfg.ACEH
	}
}

// For details about the order in which we perform the following checks,
// see https://fetch.spec.whatwg.org/#cors-preflight-fetch, item 7.
func (cfg *Config) handleCORSPreflightRequest(
	w http.ResponseWriter,
	reqHeaders http.Header,
	origins []string, // assumed non-empty
	acrm []string, // assumed non-empty
) {
	respHeaders := w.Header()
	fastAdd(respHeaders, headerVary, precomputedPreflightVaryValue)
	if !cfg.processOriginForPreflight(respHeaders, origins) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// At this stage, browsers fail the CORS-preflight check
	// (see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7)
	// if the response status is not an ok status
	// (see https://fetch.spec.whatwg.org/#ok-status).
	// If any subsequent step fails,
	// we omit the remaining CORS response headers
	// and let the browser fail the CORS-preflight fetch;
	// however, for easier troubleshooting on the client side,
	// we nonetheless respond with an ok status.
	if !cfg.processACRPN(respHeaders, reqHeaders) {
		w.WriteHeader(cfg.PreflightSuccessStatus)
		return
	}
	if !cfg.processACRM(respHeaders, acrm) {
		w.WriteHeader(cfg.PreflightSuccessStatus)
		return
	}
	if !cfg.processACRH(respHeaders, reqHeaders) {
		w.WriteHeader(cfg.PreflightSuccessStatus)
		return
	}
	if cfg.ACMA != nil {
		respHeaders[headerMageAge] = cfg.ACMA
	}
	w.WriteHeader(cfg.PreflightSuccessStatus)
}

func (cfg *Config) processOriginForPreflight(
	respHeaders http.Header,
	origins []string, // assumed non-empty
) bool {
	rawOrigin := origins[0]
	o, ok := origin.Parse(rawOrigin)
	if !ok {
		return false
	}
	if cfg.ACAO != nil { // by construction, guaranteed to be non-empty
		if !cfg.AllowAnyOrigin && cfg.ACAO[0] != rawOrigin {
			return false
		}
		respHeaders[headerAllowOrigin] = cfg.ACAO
		if cfg.AllowCredentials {
			// We make no attempt to infer whether the request is credentialed.
			respHeaders[headerAllowCredentials] = precomputedTrue
		}
		return true
	}
	if !cfg.Corpus.Contains(&o) {
		return false
	}
	respHeaders[headerAllowOrigin] = origins
	if cfg.AllowCredentials {
		// We make no attempt to infer whether the request is credentialed.
		respHeaders[headerAllowCredentials] = precomputedTrue
	}
	return true
}

// About this specific check, see
// https://wicg.github.io/private-network-access/#cors-preflight, item 4.2.
func (cfg *Config) processACRPN(respHeaders, reqHeaders http.Header) bool {
	acrpn, found := first(reqHeaders, headerRequestPrivateNetwork)
	if !found || acrpn[0] != headerValueTrue { // no request for private-network access
		return true
	}
	if !cfg.PrivateNetworkAccess && !cfg.PrivateNetworkAccessInNoCORSModeOnly {
		return false
	}
	respHeaders[headerAllowPrivateNetwork] = precomputedTrue
	return true
}

// Note: only for _non-preflight_ CORS requests
func (cfg *Config) handleNonPreflightCORSRequest(
	w http.ResponseWriter,
	origins []string, // assumed non-empty
	isOptionsReq bool,
) {
	respHeaders := w.Header()
	// see https://wicg.github.io/private-network-access/#shortlinks
	if cfg.PrivateNetworkAccessInNoCORSModeOnly {
		if isOptionsReq {
			fastAdd(respHeaders, headerVary, precomputedPreflightVaryValue)
		}
		return
	}
	switch {
	case isOptionsReq:
		fastAdd(respHeaders, headerVary, precomputedPreflightVaryValue)
	case cfg.ACAO == nil:
		fastAdd(respHeaders, headerVary, precomputedHeaderOrigin)
	}
	if cfg.ACAO != nil {
		// See the last paragraph in
		// https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		respHeaders[headerAllowOrigin] = cfg.ACAO
		if cfg.AllowCredentials {
			// We make no attempt to infer whether the request is credentialed.
			respHeaders[headerAllowCredentials] = precomputedTrue
		}
		if cfg.ACEH != nil {
			respHeaders[headerExposeHeaders] = cfg.ACEH
		}
		return
	}
	o, ok := origin.Parse(origins[0])
	if !ok || !cfg.Corpus.Contains(&o) {
		return
	}
	respHeaders[headerAllowOrigin] = origins
	if cfg.AllowCredentials {
		// We make no attempt to infer whether the request is credentialed.
		respHeaders[headerAllowCredentials] = precomputedTrue
	}
	if cfg.ACEH != nil {
		respHeaders[headerExposeHeaders] = cfg.ACEH
	}
}

func (cfg *Config) processACRM(
	headers http.Header,
	acrm []string, // assumed non-empty
) bool {
	if safelistedMethods.Contains(acrm[0]) {
		// CORS-safelisted methods get a free pass; see
		// https://fetch.spec.whatwg.org/#ref-for-cors-safelisted-method%E2%91%A2.
		// Therefore, no need to set the ACAM header in this case.
		return true
	}
	if cfg.ACAM != nil {
		headers[headerAllowMethods] = cfg.ACAM
		return true
	}
	if !cfg.AllowAnyMethod {
		return false
	}
	headers[headerAllowMethods] = acrm
	return true
}

func (cfg *Config) processACRH(respHeaders, reqHeaders http.Header) bool {
	acrh, found := first(reqHeaders, headerRequestHeaders)
	if !found {
		return true
	}
	if cfg.ACAH != nil {
		respHeaders[headerAllowHeaders] = cfg.ACAH
		return true
	}
	if !cfg.AllowAnyRequestHeaders {
		return false
	}
	// We can take a shortcut here and simply reuse the request's ACRH header.
	// Because Fetch-compliant browsers wouldn't send a malformed ACRH header,
	// we don't expect this shortcut to be detrimental to security.
	respHeaders[headerAllowHeaders] = acrh
	return true
}

// To mitigate malformed (incorrect or adversarial) CORS requests,
// we drop any subsequent values after the first occurrence (if any)
// of each request header involved in the CORS protocol.
func first(headers http.Header, name string) ([]string, bool) {
	v, found := headers[name]
	if !found || len(v) == 0 {
		return nil, false
	}
	return v[:1], true
}

func sortCombineWithComma(set util.Set[string]) string {
	// The elements of a header-field value may be separated simply by commas;
	// since whitespace is optional, let's not use any.
	// See https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#abnf.extension.recipient
	return util.SortCombine(set, string(comma))
}
