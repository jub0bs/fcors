package internal

import (
	"testing"
)

func TestThatAllForbiddenMethodsAreByteLowercase(t *testing.T) {
	for method := range byteLowercasedForbiddenMethods {
		if byteLowercase(method) != method {
			t.Errorf("forbidden method %q is not byte-lowercase", method)
		}
	}
}
