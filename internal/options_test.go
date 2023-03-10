package internal

import (
	"testing"
)

func TestThatNoneOfTheOptionAnonsImplementsOptionCred(t *testing.T) {
	// important property that prevents users from subverting
	// fcors's compile-time guarantees
	cases := []struct {
		desc string
		opt  OptionAnon
	}{
		{
			desc: optFAO,
			opt:  FromAnyOrigin(),
		}, {
			desc: optEARH,
			opt:  ExposeAllResponseHeaders(),
		}, {
			desc: optANEWS,
			opt:  AssumeNoExtendedWildcardSupport(),
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			_, ok := c.opt.(OptionCred)
			if ok {
				t.Errorf("%s() should not implements OptionCred, but it does", c.desc)
			}
		}
		t.Run(c.desc, f)
	}
}
