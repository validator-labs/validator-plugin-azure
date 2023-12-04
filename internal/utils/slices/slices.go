package slices

import "fmt"

// Vals maps a slice of pointers to their values. Returns an error if it encounters a nil pointer.
func Vals[T any](ptrs []*T) ([]T, error) {
	vals := make([]T, len(ptrs))
	for i, s := range ptrs {
		if s == nil {
			return nil, fmt.Errorf("pointer in slice was nil")
		}
		vals[i] = *s
	}
	return vals, nil
}
