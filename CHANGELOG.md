# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/jub0bs/fcors/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jub0bs/fcors/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jub0bs/fcors/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jub0bs/fcors/releases/tag/v0.1.0

[pna-rename]: https://github.com/WICG/local-network-access/issues/91
