package internal_test

import (
	"testing"
	"unsafe"

	"github.com/jub0bs/fcors/internal"
)

func TestConfigSize(t *testing.T) {
	const (
		cacheLineSizeInBytes = 64
		want                 = 3 * cacheLineSizeInBytes
	)
	got := unsafe.Sizeof(internal.Config{})
	if got != want {
		t.Errorf("want %d bytes; got %d bytes", want, got)
	}
}
