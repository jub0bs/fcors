package internal

import (
	"testing"
)

// important property that prevents users from subverting
// fcors's compile-time guarantees
func TestThatNoneOfTheOptionAnonsImplementsOption(t *testing.T) {
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
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			_, ok := c.opt.(Option)
			if ok {
				t.Errorf("%s() should not satisfy Option, but it does", c.desc)
			}
		}
		t.Run(c.desc, f)
	}
}

// Because option's cred method is never meant to be called,
// this test admittedly is a bit silly; it's needed only to
// (somewhat artificially) bridge the gap to 100% code coverage.
func TestCredMethod(_ *testing.T) {
	var opt option
	opt.cred()
}
