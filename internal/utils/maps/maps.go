// Package maps contains util code related to maps.
package maps

// FromKeys builds a map with the specified keys, where each key's value is the specified value.
func FromKeys[K comparable, V any](keys []K, value V) map[K]V {
	m := make(map[K]V, 0)
	for _, k := range keys {
		m[k] = value
	}
	return m
}
