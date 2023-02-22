package internal

import (
	"strconv"

	"github.com/jub0bs/fcors/internal/origin"
	"github.com/jub0bs/fcors/internal/util"
	"golang.org/x/exp/maps"
)

const (
	optANEWS   = "AssumeNoExtendedWildcardSupport"
	optANWCOPR = "AssumeNoWebCachingOfPreflightResponses"
	optEARH    = "ExposeAllResponseHeaders"
	optERH     = "ExposeResponseHeaders"
	optFAO     = "FromAnyOrigin"
	optFO      = "FromOrigins"
	optPNA     = "PrivateNetworkAccess"
	optPNANC   = "PrivateNetworkAccessInNoCorsModeOnly"
	optSIOC    = "TolerateInsecureOrigins"
	optSPSC    = "SkipPublicSuffixCheck"
	optWAM     = "WithAnyMethod"
	optWARH    = "WithAnyRequestHeaders"
	optWM      = "WithMethods"
	optWMAIS   = "MaxAgeInSeconds"
	optWPSS    = "PreflightSuccessStatus"
	optWRH     = "WithRequestHeaders"
)

type Option interface {
	OptionAnon
	OptionCred
}

type option func(*Config) error

func (f option) applyAnon(c *Config) error {
	return f(c)
}

func (f option) applyCred(c *Config) error {
	return f(c)
}

type OptionAnon interface {
	applyAnon(*Config) error
}

// We need a concrete type dedicated to the OptionAnon type
// and distinct from the option type
// because we want to prevent users from type-asserting
// Option values (like that returned by AllowAnyOrigin)
// to the OptionCred type.
type optionAnon func(*Config) error

func (f optionAnon) applyAnon(c *Config) error {
	return f(c)
}

type OptionCred interface {
	applyCred(*Config) error
}

func AllowAccess(opts ...OptionAnon) (Middleware, error) {
	cfg := newConfig(false)
	for _, opt := range opts {
		err := opt.applyAnon(cfg)
		if err != nil {
			return nil, err
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.precomputeStuff()
	return cfg.middleware(), nil
}

func AllowAccessWithCredentials(opts ...OptionCred) (Middleware, error) {
	cfg := newConfig(true)
	for _, opt := range opts {
		err := opt.applyCred(cfg)
		if err != nil {
			return nil, err
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.precomputeStuff()
	return cfg.middleware(), nil
}

func FromOrigins(first string, others ...string) Option {
	var (
		setOfSpecs                         = make(util.Set[origin.Spec])
		publicSuffixError                  error
		insecureOriginPatternError         error
		firstPatternSpecifiedMultipleTimes string
		nonWildcardOrigin                  string
	)
	processOnePattern := func(pattern string) error {
		spec, err := origin.ParseSpec(pattern)
		if err != nil {
			return err
		}
		if spec.IsDeemedInsecure() && insecureOriginPatternError == nil {
			const tmpl = "most origin patterns like %q that use " +
				"insecure scheme %q are by default prohibited"
			insecureOriginPatternError = util.Errorf(tmpl, pattern, spec.Scheme)
		}
		if !spec.Kind.ArbitrarySubdomains() && nonWildcardOrigin == "" {
			nonWildcardOrigin = pattern
		}
		if spec.Kind.ArbitrarySubdomains() {
			eTLD, isEffectiveTLD := spec.HostIsEffectiveTLD()
			if isEffectiveTLD && publicSuffixError == nil {
				const tmpl = "origin patterns like %q that allow arbitrary " +
					"subdomains of public suffix %q are by default prohibited"
				publicSuffixError = util.Errorf(tmpl, pattern, eTLD)
			}
		}
		if setOfSpecs.Contains(*spec) {
			firstPatternSpecifiedMultipleTimes = pattern
			return nil
		}
		setOfSpecs.Add(*spec)
		return nil
	}
	if err := processOnePattern(first); err != nil {
		return option(invariablyReturn(err))
	}
	for _, pattern := range others {
		if err := processOnePattern(pattern); err != nil {
			return option(invariablyReturn(err))
		}
	}
	f := func(cfg *Config) error {
		if !cfg.Corpus.IsEmpty() || cfg.tmp.SingleNonWildcardOrigin != "" {
			return util.NewError("option " + optFO + " used multiple times")
		}
		if firstPatternSpecifiedMultipleTimes != "" {
			const tmpl = "origin pattern %q specified multiple times"
			return util.Errorf(tmpl, firstPatternSpecifiedMultipleTimes)
		}
		cfg.tmp.InsecureOriginPatternError = insecureOriginPatternError
		cfg.tmp.PublicSuffixError = publicSuffixError
		if len(setOfSpecs) == 1 && nonWildcardOrigin != "" {
			// special case in which we don't need a corpus at all
			cfg.tmp.SingleNonWildcardOrigin = nonWildcardOrigin
			return nil
		}
		corpus := make(origin.Corpus)
		for spec := range setOfSpecs {
			corpus.Add(&spec)
		}
		cfg.Corpus = corpus
		return nil
	}
	return option(f)
}

func FromAnyOrigin() OptionAnon {
	f := func(cfg *Config) error {
		if cfg.AllowArbitraryOrigins {
			return util.NewError("option " + optFAO + " used multiple times")
		}
		cfg.AllowArbitraryOrigins = true
		return nil
	}
	return optionAnon(f)
}

func WithMethods(first string, others ...string) Option {
	sizeHint := 1 + len(others) // there may be dupes, but that's the user's fault
	allowedMethods := make(util.Set[string], sizeHint)
	if err := processOneMethod(first, allowedMethods); err != nil {
		return option(invariablyReturn(err))
	}
	for _, m := range others {
		if err := processOneMethod(m, allowedMethods); err != nil {
			return option(invariablyReturn(err))
		}
	}
	// Because safelisted methods need not be explicitly allowed
	// (see https://stackoverflow.com/a/71429784/2541573),
	// let's remove them silently.
	maps.DeleteFunc(allowedMethods, isSafelisted)
	f := func(cfg *Config) error {
		if cfg.tmp.AllowedMethods != nil {
			return util.NewError("option " + optWM + " used multiple times")
		}
		cfg.tmp.AllowedMethods = allowedMethods
		return nil
	}
	return option(f)
}

func isSafelisted(method string, _ struct{}) bool {
	return safelistedMethods.Contains(method)
}

func processOneMethod(name string, allowedMethods util.Set[string]) error {
	if !isValidMethod(name) {
		return util.Errorf("invalid method name %q", name)
	}
	if name == wildcard {
		return util.Errorf(`disallowed method name "*"`)
	}
	if byteLowercasedForbiddenMethods.Contains(byteLowercase(name)) {
		return util.Errorf("forbidden method name %q", name)
	}
	if allowedMethods.Contains(name) {
		return util.Errorf("method name %q specified multiple times", name)
	}
	allowedMethods.Add(name)
	return nil
}

func WithAnyMethod() Option {
	f := func(cfg *Config) error {
		if cfg.AllowArbitraryMethods {
			return util.NewError("option " + optWAM + " used multiple times")
		}
		cfg.AllowArbitraryMethods = true
		return nil
	}
	return option(f)
}

func WithRequestHeaders(first string, others ...string) Option {
	sizeHint := 1 + len(others) // there may be dupes, but that's the user's fault
	allowedHeaders := make(util.Set[string], sizeHint)
	if err := processOneRequestHeader(first, allowedHeaders); err != nil {
		return option(invariablyReturn(err))
	}
	for _, name := range others {
		if err := processOneRequestHeader(name, allowedHeaders); err != nil {
			return option(invariablyReturn(err))
		}
	}
	f := func(cfg *Config) error {
		if cfg.tmp.AllowedRequestHeaders != nil {
			return util.NewError("option " + optWRH + " used multiple times")
		}
		cfg.tmp.AllowedRequestHeaders = allowedHeaders
		return nil
	}
	return option(f)
}

func processOneRequestHeader(name string, allowedHeaders util.Set[string]) error {
	if !isValidHeaderName(name) {
		return util.Errorf("invalid request-header name %q", name)
	}
	// Fetch-compliant browsers byte-lowercase header names
	// before writing them to the ACRH header; see
	// https://fetch.spec.whatwg.org/#cors-unsafe-request-header-names,
	// step 6.
	name = byteLowercase(name)
	if isForbiddenRequestHeaderName(name) {
		return util.Errorf("forbidden request-header name %q", name)
	}
	if disallowedRequestHeaderNames.Contains(name) {
		return util.Errorf("disallowed request-header name %q", name)
	}
	if allowedHeaders.Contains(name) {
		return util.Errorf("request-header name %q specified multiple times", name)
	}
	allowedHeaders.Add(name)
	return nil
}

func WithAnyRequestHeaders() Option {
	f := func(cfg *Config) error {
		if cfg.AllowArbitraryRequestHeaders {
			return util.NewError("option " + optWARH + " used multiple times")
		}
		cfg.AllowArbitraryRequestHeaders = true
		return nil
	}
	return option(f)
}

func MaxAgeInSeconds(delta uint) Option {
	// Current upper bounds:
	//  - Firefox:         86400 (24h)
	//  - Chromium:         7200 (2h)
	//  - WebKit/Safari:     600 (10m)
	//     see https://github.com/WebKit/WebKit/blob/6c4c981002fe98d371b03ab862b589120661a63d/Source/WebCore/loader/CrossOriginPreflightResultCache.cpp#L42
	const upperBound = 86400
	if delta > upperBound {
		const tmpl = "specified max-age value %d exceeds upper bound %d"
		return option(invariablyReturn(util.Errorf(tmpl, delta, upperBound)))
	}
	f := func(cfg *Config) error {
		if cfg.ACMA != nil {
			return util.NewError("option " + optWMAIS + " used multiple times")
		}
		const base = 10
		cfg.ACMA = []string{strconv.FormatUint(uint64(delta), base)}
		return nil
	}
	return option(f)
}

func ExposeResponseHeaders(first string, others ...string) Option {
	exposedHeaders := make(util.Set[string], len(others))
	if err := processOneResponseHeader(first, exposedHeaders); err != nil {
		return option(invariablyReturn(err))
	}
	for _, name := range others {
		if err := processOneResponseHeader(name, exposedHeaders); err != nil {
			return option(invariablyReturn(err))
		}
	}
	precomputed := []string{util.SortCombine(exposedHeaders, string(comma))}
	f := func(cfg *Config) error {
		if cfg.ACEH != nil {
			return util.NewError("option " + optERH + " used multiple times")
		}
		cfg.ACEH = precomputed
		return nil
	}
	return option(f)
}

func processOneResponseHeader(name string, exposedHeaders util.Set[string]) error {
	if !isValidHeaderName(name) {
		return util.Errorf("invalid response-header name %q", name)
	}
	name = byteLowercase(name)
	if forbiddenResponseHeaderNames.Contains(name) {
		return util.Errorf("forbidden response-header name %q", name)
	}
	if disallowedResponseHeaderNames.Contains(name) {
		return util.Errorf("disallowed response-header name %q", name)
	}
	if safelistedResponseHeaderNames.Contains(name) {
		const tmpl = "response-header name %q needs not be explicitly exposed"
		return util.Errorf(tmpl, name)
	}
	if exposedHeaders.Contains(name) {
		return util.Errorf("response-header name %q specified multiple times", name)
	}
	exposedHeaders.Add(name)
	return nil
}

func ExposeAllResponseHeaders() OptionAnon {
	f := func(cfg *Config) error {
		if cfg.ExposeAllResponseHeaders {
			return util.NewError("option " + optEARH + " used multiple times")
		}
		cfg.ExposeAllResponseHeaders = true
		return nil
	}
	return optionAnon(f)
}

func AssumeNoExtendedWildcardSupport() OptionAnon {
	f := func(cfg *Config) error {
		if cfg.tmp.AssumeNoExtendedWildcardSupport {
			return util.NewErrorRisky("option " + optANEWS + " used multiple times")
		}
		cfg.tmp.AssumeNoExtendedWildcardSupport = true
		return nil
	}
	return optionAnon(f)
}

func PreflightSuccessStatus(status uint) Option {
	// see https://fetch.spec.whatwg.org/#ok-status
	if !(200 <= status && status < 300) {
		const tmpl = "specified status %d outside the 2xx range"
		return option(invariablyReturn(util.Errorf(tmpl, status)))
	}
	f := func(cfg *Config) error {
		if cfg.tmp.CustomPreflightSuccessStatus {
			return util.NewError("option " + optWPSS + " used multiple times")
		}
		cfg.tmp.CustomPreflightSuccessStatus = true
		s := int(status) // this conversion is safe because status < 300
		cfg.PreflightSuccessStatus = s
		return nil
	}
	return option(f)
}

func AssumeNoWebCachingOfPreflightResponses() Option {
	f := func(cfg *Config) error {
		if cfg.AssumeNoWebCachingOfPreflightResponses {
			return util.NewErrorRisky("option " + optANWCOPR + " used multiple times")
		}
		cfg.AssumeNoWebCachingOfPreflightResponses = true
		return nil
	}
	return option(f)
}

func PrivateNetworkAccess() Option {
	// blanket policy that applies to all origins
	// see https://github.com/WICG/private-network-access/issues/84
	f := func(cfg *Config) error {
		if cfg.PrivateNetworkAccess {
			return util.NewErrorRisky("option " + optPNA + " used multiple times")
		}
		cfg.PrivateNetworkAccess = true
		return nil
	}
	return option(f)
}

func PrivateNetworkAccessInNoCorsModeOnly() Option {
	f := func(cfg *Config) error {
		if cfg.PrivateNetworkAccessInNoCorsModeOnly {
			return util.NewErrorRisky("option " + optPNANC + " used multiple times")
		}
		cfg.PrivateNetworkAccessInNoCorsModeOnly = true
		return nil
	}
	return option(f)
}

func TolerateInsecureOrigins() Option {
	f := func(cfg *Config) error {
		if cfg.tmp.TolerateInsecureOrigins {
			return util.NewErrorRisky("option " + optSIOC + " used multiple times")
		}
		cfg.tmp.TolerateInsecureOrigins = true
		return nil
	}
	return option(f)
}

func SkipPublicSuffixCheck() Option {
	f := func(cfg *Config) error {
		if cfg.tmp.SkipPublicSuffixCheck {
			return util.NewErrorRisky("option " + optSPSC + " used multiple times")
		}
		cfg.tmp.SkipPublicSuffixCheck = true
		return nil
	}
	return option(f)
}

func invariablyReturn(err error) func(*Config) error {
	return func(_ *Config) error {
		return err
	}
}
