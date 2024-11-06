// Package strings has utility code related to strings.
package strings

import "github.com/google/uuid"

// IsValidUUID checks whether a string is a valid v4 UUID.
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
