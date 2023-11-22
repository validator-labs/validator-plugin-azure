package strings

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

// AnyNil returns whether any of the string pointers in a slice of string pointers are nil.
func AnyNil(strs []*string) bool {
	for _, s := range strs {
		if s == nil {
			return true
		}
	}
	return false
}
