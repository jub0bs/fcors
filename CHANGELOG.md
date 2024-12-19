# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2] (2024-12-19)

### Fixed

- **Build**: eschew Gosec in GitHub Action (too many false positives)

## [0.9.1] (2024-12-19)

### Changed

- **Dependencies**: update to `golang.org/x/net` v0.33.0
- **Documentation**: minor fixes

## [0.9.0] (2024-05-02)

### Fixed

- **Vulnerability**: Some CORS middleware (more specifically those created
  by specifying two or more origin patterns whose hosts share a proper suffix)
  incorrectly allowed some untrusted origins, thereby opening the door to
  cross-origin attacks from the untrusted origins in question.
  For example, specifying origin patterns `https://foo.com` and
  `https://bar.com` (in that order) would yield a middleware that would
  incorrectly allow untrusted origin `https://barfoo.com`.
  See https://github.com/jub0bs/fcors/security/advisories/GHSA-v84h-653v-4pq9.

### Changed

- **API** (breaking changes): option `PrivateNetworkAccessInNoCorsModeOnly`
  has been renamed to `PrivateNetworkAccessInNoCORSModeOnly`.
- **API** (breaking changes): option `SkipPublicSuffixCheck`
  has been renamed to `DangerouslyTolerateSubdomainsOfPublicSuffixes`.
  - **API** (breaking changes): option `TolerateInsecureOrigins`
  has been renamed to `DangerouslyTolerateInsecureOrigins`.
- **Dependencies**: update to `golang.org/x/net` v0.24.0
- **Documentation**: recommend migration to [jub0bs/cors][cors] in README
- **Documentation**: match examples from [jub0bs/cors][cors]
- **Documentation**: various improvements
- **Behavior**: improve error messages
- **Behavior**: Relax the need to activate option
  `DangerouslyTolerateInsecureOrigins`; it is now required only if you specify
  insecure origin patterns and enable credentialed access and/or some form of
  Private Network Access.
- **Performance**: minor improvements

### Removed

- **API** (breaking change): option `AssumeNoWebCachingOfPreflightResponses`
- **API** (breaking change): option `AssumeNoExtendedWildcardSupport`
- **Documentation**: links to external examples and benchmarks in README

## [0.8.0] (2024-02-08)

### Changed

- **Dependencies**: update to `golang.org/x/net` v0.20.0
- **API**: A single leading asterisk (followed by a period) preceding the host
  part of an origin pattern now denotes, not exactly one, but one or more
  arbitrary DNS labels.
- **Behavior**: Duplicate origin patterns are now tolerated.
- **Behavior**: Duplicate HTTP methods are now tolerated.
- **Behavior**: Duplicate request-header names are now tolerated.
- **Behavior**: Duplicate response-header names are now tolerated.
- **Behavior**: Exposing preflight response-header names is now prohibited.
- **Performance**: Middleware initialization incurs fewer allocations.
- **Performance**: Origin matching is overall faster, even in cases that used
  to be pathological in earlier versions.
- **Documentation**: various improvements

### Removed

- **API** (breaking change): Two consecutive asterisks (**) are no longer
  supported in origin patterns.

## [0.7.0] (2023-11-18)

### Changed

- **Dependencies**: Go 1.21 (or above) is now required.
- **Dependencies**: remove dependency on `golang.org/x/exp`
- **Dependencies**: update to `golang.org/x/net` v0.18.0
- **Documentation**: various improvements
- **Tests**: improve test and benchmark suites.

## [0.6.0] (2023-08-01)

### Changed

- **Dependencies**: update to `golang.org/x/exp`
  v0.0.0-20230801115018-d63ba01acd4b
- **Documentation**: no longer mention Twitter in the security policy.
- **Documentation**: minor improvements
- **Performance**: middleware invocations now only incur heap allocations
  in rare cases; more specifically, allocations only occur
  if the CORS middleware allows multiple origins
  and another middleware up the chain adds a `Vary` header to responses.
- **Tests**: improve test and benchmark suites.

### Removed

- **API** (breaking change): interface type `OptionCred`.

## [0.5.1] (2023-07-17)

### Changed

- **Dependencies**: update to `golang.org/x/net` v0.12.0
  and `golang.org/x/exp` v0.0.0-20230713183714-613f0c0eb8a1
- **Documentation**: minor improvements

## [0.5.0] (2023-07-10)

### Added

- **API**: options `PrivateNetworkAccess` and
  `PrivateNetworkAccessInNoCorsModeOnly`.

### Changed

- **Behavior**: in light of [the W3C's recent rename][pna-rename2]
  of "Local Network Access" to "Private Network Access",
  middleware no longer support
  the `Access-Control-Request-Local-Network`
  and `Access-Control-Allow-Local-Network` headers.
- **Behavior**: `Access-Control-Request-Local-Network`
  no longer is a forbidden request-header name.
- **Documentation**: add section entitled 'Praise for fcors' in README.
- **Documentation**: minor cosmetic and wording improvements in README

### Removed

- **API** (breaking changes):
  options `LocalNetworkAccess` and `LocalNetworkAccessInNoCorsModeOnly`
  have respectively been renamed to
  `PrivateNetworkAccess` and `PrivateNetworkAccessInNoCorsModeOnly`.

## [0.4.0] (2023-05-01)

## Added

- **Tests**: improve and augment test suite.

### Changed

- **Behavior**: in accordance with
  [recent changes to the Local-Network-Access spec][pna-earlier]
  and in light of Chromium's pre-existing implementation of that behavior,
  the relevant LNA check is now performed earlier
  (right after the CORS check)
  in order to ease troubleshooting on the client side.

## [0.3.1] (2023-03-16)

## Added

- **Documentation**: link to [jub0bs/fcors-examples][examples] in README.

### Changed

- **Documentation**: fix minimum Go version required in README.
- **Tests**: some typo fixes

## [0.3.0] (2023-03-03)

### Added

- **Documentation**: option `MaxAgeInSeconds` now documents the upper bound
  (86400) it places on its argument.

### Changed

- **Dependencies**: Go 1.20 (or above) is now required.
- **Behavior**: functions `AllowAccess` and `AllowAccessWithCredentials`
  now return a multierror that lists all the reasons (if any)
  for which configuration failed.
- **Behavior**: `Access-Control-Allow-Local-Network` and
  `Access-Control-Request-Local-Network` are now disallowed
  as request-header and response-header names, respectively.
- **Behavior**: simplification of some error messages
- **Documentation**: minor improvements to examples
- **Documentation**: minor documentation fix for option
  `risky.AssumeNoExtendedWildcardSupport`

## [0.2.0] (2023-02-25)

### Added

- **API**: options `LocalNetworkAccess` and
  `LocalNetworkAccessInNoCorsModeOnly`.

### Changed

- **API** (breaking changes):
  functions `AllowAccess` and `AllowAccessWithCredentials`
  now require at least one option.
- **Behavior**: in light of [the W3C's recent rename][pna-rename]
  of "Private Network Access" to "Local Network Access",
  middleware now support
  the `Access-Control-Request-Local-Network`
  and `Access-Control-Allow-Local-Network` headers
  in addition to
  the `Access-Control-Request-Private-Network`
  and `Access-Control-Allow-Private-Network` headers.
- **Behavior**: `Access-Control-Request-Local-Network`
  is now a forbidden request-header name.
- **Documentation**: the parameter names of variadic functions and methods
  have been simplified and unified.
- **Documentation**: minor wording improvements in README

### Removed

- **API** (breaking changes):
  options `PrivateNetworkAccess` and `PrivateNetworkAccessInNoCorsModeOnly`
  have respectively been renamed to
  `LocalNetworkAccess` and `LocalNetworkAccessInNoCorsModeOnly`.

## [0.1.1] (2023-02-22)

### Added

- **Documentation**: some typo fixes
- **Documentation**: expand guidelines about middleware usage
- **Documentation**: document that default ports should be elided
  in origin patterns
- **Documentation**: document middleware concurrency safety
- **Documentation**: minor formatting improvements

### Changed

- **Dependencies**: update to `golang.org/x/net` v0.7.0
  and `golang.org/x/exp` v0.0.0-20230213192124-5e25df0256eb

## [0.1.0] (2023-02-08)

[0.9.2]: https://github.com/jub0bs/fcors/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/jub0bs/fcors/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/jub0bs/fcors/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jub0bs/fcors/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jub0bs/fcors/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jub0bs/fcors/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/jub0bs/fcors/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/jub0bs/fcors/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jub0bs/fcors/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/jub0bs/fcors/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jub0bs/fcors/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jub0bs/fcors/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jub0bs/fcors/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jub0bs/fcors/releases/tag/v0.1.0

[cors]: https://github.com/jub0bs/cors
[examples]: https://github.com/jub0bs/fcors-examples
[pna-earlier]: https://github.com/WICG/private-network-access/pull/90
[pna-rename]: https://github.com/WICG/private-network-access/issues/91
[pna-rename2]: https://github.com/WICG/private-network-access/pull/106
