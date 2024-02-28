package origin

import (
	"github.com/jub0bs/fcors/internal/radix"
)

// A Corpus represents a set of allowed (tuple) [Web origins].
// The keys in this map correspond to origin schemes.
type Corpus map[string]radix.Tree

func (c Corpus) Add(pattern *Pattern) {
	tree := c[pattern.Scheme]
	tree.Insert(pattern.Value, pattern.Port)
	c[pattern.Scheme] = tree
}

func (c Corpus) Contains(o *Origin) bool {
	tree, found := c[o.Scheme]
	return found && tree.Contains(o.Value, o.Port)
}
