package strings

import "fmt"

// DeDupeStrSlice deduplicates a slices of strings
func DeDupeStrSlice(ss []string) []string {
	found := make(map[string]bool)
	l := []string{}
	for _, s := range ss {
		if _, ok := found[s]; !ok {
			found[s] = true
			l = append(l, s)
		}
	}
	return l
}

// Contains returns whether a string is contained within a slice of string pointers, with respect to
// equality (not identity).
//   - s: The candidate slice of string pointers. Nil values allowed.
//   - c: The candidate string.
func ContainsPtrToEqlTo(strPtrs []*string, c string) bool {
	for _, strPtr := range strPtrs {
		if strPtr != nil && *strPtr == c {
			return true
		}
	}
	return false
}

// ToVals maps a slice of string pointers to their string values. Returns an error if it encounters
// a nil pointer.
func ToVals(strs []*string) ([]string, error) {
	vals := make([]string, len(strs))
	for i, s := range strs {
		if s == nil {
			return nil, fmt.Errorf("pointer in slice was nil")
		}
		vals[i] = *s
	}
	return vals, nil
}
