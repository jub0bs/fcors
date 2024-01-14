package internal

import (
	"errors"
	"maps"
	"strconv"

	"github.com/jub0bs/fcors/internal/origin"
	"github.com/jub0bs/fcors/internal/util"
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
	applier
	// cred is a no-op function whose sole purpose is to guarantee that
	// Option strictly subsume OptionAnon.
	cred()
}

type option func(*Config) error

func (f option) apply(cfg *Config) error {
	return f(cfg)
}

func (option) cred() {}

var _ Option = (option)(nil)

type OptionAnon interface {
	applier
}

// A concrete type that satisfies OptionAnon but does not satisfy Option.
// We need this distinct type because we want to prevent users
// from type-asserting OptionAnon values (like that returned by FromAnyOrigin)
// to the Option type.
type optionAnon func(*Config) error

func (f optionAnon) apply(cfg *Config) error {
	return f(cfg)
}

var _ OptionAnon = (optionAnon)(nil)

type applier interface {
	apply(*Config) error
}

func NewMiddleware[A applier](cred bool, one A, others ...A) (Middleware, error) {
	cfg := newConfig(cred)
	var errs []error
	if err := one.apply(cfg); err != nil {
		errs = append(errs, err)
	}
	for _, opt := range others {
		if err := opt.apply(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	if err := cfg.validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	cfg.precomputeStuff()
	return cfg.middleware(), nil
}

func FromOrigins(one string, others ...string) Option {
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
	f := func(cfg *Config) error {
		var errs []error
		if err := processOnePattern(one); err != nil {
			errs = append(errs, err)
		}
		for _, pattern := range others {
			if err := processOnePattern(pattern); err != nil {
				errs = append(errs, err)
			}
		}
		if cfg.tmp.FromOriginsCalled {
			err := util.NewError("option " + optFO + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.FromOriginsCalled = true
		if firstPatternSpecifiedMultipleTimes != "" {
			const tmpl = "origin pattern %q specified multiple times"
			err := util.Errorf(tmpl, firstPatternSpecifiedMultipleTimes)
			errs = append(errs, err)
		}
		cfg.tmp.InsecureOriginPatternError = insecureOriginPatternError
		cfg.tmp.PublicSuffixError = publicSuffixError
		if len(errs) != 0 {
			return errors.Join(errs...)
		}
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
		if cfg.AllowAnyOrigin {
			return util.NewError("option " + optFAO + " used multiple times")
		}
		cfg.AllowAnyOrigin = true
		return nil
	}
	return optionAnon(f)
}

func WithMethods(one string, others ...string) Option {
	f := func(cfg *Config) error {
		sizeHint := 1 + len(others) // there may be dupes, but that's the user's fault
		allowedMethods := make(util.Set[string], sizeHint)
		var errs []error
		if err := processOneMethod(one, allowedMethods); err != nil {
			errs = append(errs, err)
		}
		for _, m := range others {
			if err := processOneMethod(m, allowedMethods); err != nil {
				errs = append(errs, err)
			}
		}
		// Because safelisted methods need not be explicitly allowed
		// (see https://stackoverflow.com/a/71429784/2541573),
		// let's remove them silently.
		maps.DeleteFunc(allowedMethods, isSafelisted)
		if cfg.tmp.WithMethodsCalled {
			err := util.NewError("option " + optWM + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.WithMethodsCalled = true
		if len(errs) != 0 {
			return errors.Join(errs...)
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
		return util.Errorf(`prohibited method name "*"`)
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
		if cfg.AllowAnyMethod {
			return util.NewError("option " + optWAM + " used multiple times")
		}
		cfg.AllowAnyMethod = true
		return nil
	}
	return option(f)
}

func WithRequestHeaders(one string, others ...string) Option {
	f := func(cfg *Config) error {
		sizeHint := 1 + len(others) // there may be dupes, but that's the user's fault
		allowedHeaders := make(util.Set[string], sizeHint)
		var errs []error
		if err := processOneRequestHeader(one, allowedHeaders); err != nil {
			errs = append(errs, err)
		}
		for _, name := range others {
			if err := processOneRequestHeader(name, allowedHeaders); err != nil {
				errs = append(errs, err)
			}
		}
		if cfg.tmp.WithRequestHeadersCalled {
			err := util.NewError("option " + optWRH + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.WithRequestHeadersCalled = true
		if len(errs) != 0 {
			return errors.Join(errs...)
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
	if prohibitedRequestHeaderNames.Contains(name) {
		return util.Errorf("prohibited request-header name %q", name)
	}
	if allowedHeaders.Contains(name) {
		return util.Errorf("request-header name %q specified multiple times", name)
	}
	allowedHeaders.Add(name)
	return nil
}

func WithAnyRequestHeaders() Option {
	f := func(cfg *Config) error {
		if cfg.AllowAnyRequestHeaders {
			return util.NewError("option " + optWARH + " used multiple times")
		}
		cfg.AllowAnyRequestHeaders = true
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
	f := func(cfg *Config) error {
		var errs []error
		if delta > upperBound {
			const tmpl = "specified max-age value %d exceeds upper bound %d"
			err := util.Errorf(tmpl, delta, upperBound)
			errs = append(errs, err)
		}
		if cfg.tmp.MaxAgeInSecondsCalled {
			err := util.NewError("option " + optWMAIS + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.MaxAgeInSecondsCalled = true
		if len(errs) != 0 {
			return errors.Join(errs...)
		}
		const base = 10
		cfg.ACMA = []string{strconv.FormatUint(uint64(delta), base)}
		return nil
	}
	return option(f)
}

func ExposeResponseHeaders(one string, others ...string) Option {
	f := func(cfg *Config) error {
		exposedHeaders := make(util.Set[string], len(others))
		var errs []error
		if err := processOneResponseHeader(one, exposedHeaders); err != nil {
			errs = append(errs, err)
		}
		for _, name := range others {
			if err := processOneResponseHeader(name, exposedHeaders); err != nil {
				errs = append(errs, err)
			}
		}
		if cfg.tmp.ExposeResponseHeadersCalled {
			err := util.NewError("option " + optERH + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.ExposeResponseHeadersCalled = true
		if len(errs) != 0 {
			return errors.Join(errs...)
		}
		cfg.ACEH = []string{util.SortCombine(exposedHeaders, string(comma))}
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
	if prohibitedResponseHeaderNames.Contains(name) {
		return util.Errorf("prohibited response-header name %q", name)
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
	f := func(cfg *Config) error {
		var errs []error
		// see https://fetch.spec.whatwg.org/#ok-status
		if !(200 <= status && status < 300) {
			const tmpl = "specified status %d outside the 2xx range"
			errs = append(errs, util.Errorf(tmpl, status))
		}
		if cfg.tmp.CustomPreflightSuccessStatus {
			err := util.NewError("option " + optWPSS + " used multiple times")
			errs = append(errs, err)
		}
		cfg.tmp.CustomPreflightSuccessStatus = true
		if len(errs) != 0 {
			return errors.Join(errs...)
		}
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
