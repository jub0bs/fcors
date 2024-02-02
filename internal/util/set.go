package util

import (
	"slices"
	"strings"
)

// A Set represents a mathematical set whose elements have type E.
// Don't expect this type to work properly for elements that are
// not reflexive for equality.
type Set[E comparable] map[E]struct{}

// NewSet returns a Set that contains all of es (and no other elements).
func NewSet[E comparable](first E, rest ...E) Set[E] {
	set := make(Set[E], 1+len(rest))
	set.Add(first)
	for _, e := range rest {
		set.Add(e)
	}
	return set
}

// Add adds e to s.
func (s Set[E]) Add(e E) {
	s[e] = struct{}{}
}

// Contains returns true if e is an element of s, and false otherwise.
func (s Set[E]) Contains(e E) bool {
	_, found := s[e]
	return found
}

// SortCombine sorts the elements of s in lexicographical order,
// joins them with delim, and returns the resulting string.
func SortCombine(s Set[string], delim string) string {
	elems := toSlice(s)
	slices.Sort(elems)
	return strings.Join(elems, delim)
}

// toSlice returns the elements of the set s.
// The elements will be in an indeterminate order.
func toSlice[E comparable](s Set[E]) []E {
	elems := make([]E, 0, len(s))
	for e := range s {
		elems = append(elems, e)
	}
	return elems
}
