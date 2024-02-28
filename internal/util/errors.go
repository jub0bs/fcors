package util

import (
	"errors"
	"fmt"
)

const (
	pkgFcors = "fcors"
	pkgRisky = "risky"
)

// Errorf works the same way as [fmt.Errorf] does, but
// prefixes the resulting error message with "fcors: ".
func Errorf(format string, a ...any) error {
	format = fmt.Sprintf("%s: %s", pkgFcors, format)
	return fmt.Errorf(format, a...)
}

// NewError works the same way as [errors.New] does, but
// prefixes the resulting error message with "fcors: ".
func NewError(text string) error {
	text = fmt.Sprintf("%s: %s", pkgFcors, text)
	return errors.New(text)
}

// NewError works the same way as [errors.New] does, but
// prefixes the resulting error message with "fcors/risky: ".
func NewErrorRisky(text string) error {
	text = fmt.Sprintf("%s/%s: %s", pkgFcors, pkgRisky, text)
	return errors.New(text)
}

// InvalidOriginPatternErr returns an error about invalid origin pattern s.
func InvalidOriginPatternErr(s string) error {
	return Errorf("invalid origin pattern %q", s)
}
