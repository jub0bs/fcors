package internal

import (
	"strings"

	"golang.org/x/net/http/httpguts"
)

func isToken(raw string) bool {
	if len(raw) == 0 {
		return false
	}
	for _, b := range []byte(raw) {
		if !httpguts.IsTokenRune(rune(b)) {
			return false
		}
	}
	return true
}

func byteLowercase(s string) string {
	return strings.Map(byteLowercaseOne, s)
}

func byteLowercaseOne(asciiRune rune) rune {
	const toLower = 'a' - 'A'
	if 'A' <= asciiRune && asciiRune <= 'Z' {
		return asciiRune + toLower
	}
	return asciiRune
}
