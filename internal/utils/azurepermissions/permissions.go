package azurepermissions

import (
	"fmt"
	"strings"
)

const (
	wildcard = "*"
)

func allCandidateOperationsPermitted(operations, actions, notActions []string) (bool, error) {
	// Create a map of strings and bools, with a key for every operation. Default each value to
	// false. They will be changed later to true if the set of actions allows them, and then set
	// back to false if the set of not actions unallows them.
	operationsPermitted := MapWithAllFalse(operations)

	// Validate specified operations, action data, and not action data.
	for _, o := range operations {
		if len(o) == 0 {
			return false, fmt.Errorf("invalid operation in specified permissions, is empty string")
		}
		if numWildcards(o) > 0 {
			return false, fmt.Errorf("invalid operation in specified permissions, has one or more wildcards")
		}
	}
	for _, a := range actions {
		if len(a) == 0 {
			return false, fmt.Errorf("invalid operation in set of actions in role's permissions, is empty string")
		}
		if numWildcards(a) > 1 {
			return false, fmt.Errorf("invalid operation in set of actions in role's permissions, has multiple  wildcards")
		}
	}
	for _, na := range notActions {
		if len(na) == 0 {
			return false, fmt.Errorf("invalid operation in set of not actions in role's permissions, is empty string")
		}
		if numWildcards(na) > 1 {
			return false, fmt.Errorf("invalid operation in set of not actions in role's permissions, has multiple wildcards")
		}
	}

	// Now we know all data is valid. We can figure out, for each operation, whether it should be
	// permitted based on the actions.
	for _, operation := range operations {
		permitOperation := func() {
			operationsPermitted[operation] = true
		}

		for _, allowedAction := range actions {
			if !hasWildcard(allowedAction) {
				// If allowed action has no wildcard, candidate operation must be equal to it
				// exactly in order for it to permit it.
				if operation == allowedAction {
					permitOperation()
				}
				// Whether the action permitted the operation because it was equal to it or it
				// didn't we can move on to the next action, because if it has no wildcard, it is
				// impossible for it to permit the operation via wildcard.
				break
			}

			// Special case for when string is just a single char - the wildcard.
			if len(allowedAction) == 1 && allowedAction == wildcard {
				permitOperation()
				break
			}

			// If allowed action string has a wildcard, candidate operation must match when we take
			// the wildcard into account.

			if allowedAction[0:1] == wildcard {
				// Wildcard is at beginning of allowed action. No prefix in action string to take
				// into account.
				// Find the suffix of the action string. If that suffix is also a suffix of the
				// candidate operation, permit the operation.
				actionSuffix := strings.TrimPrefix(allowedAction, wildcard)
				if strings.HasSuffix(operation, actionSuffix) {
					permitOperation()
					break
				}
			}

			if allowedAction[len(allowedAction)-1:] == wildcard {
				// Wildcard is at end of allowed action. No suffix in action string to take into
				// account.
				// Find the prefix of the action string. If that prefix is also a prefix of the
				// candidate operation, permit the operation.
				actionPrefix := strings.TrimSuffix(allowedAction, wildcard)
				if strings.HasPrefix(operation, actionPrefix) {
					permitOperation()
					break
				}
			}

			// Wildcard is somewhere in the middle. Must take into account prefix and suffix.
			// Split the action string by the wildcard. The first segment is a prefix. The second is
			// a suffix. If the candidate operation has this prefix as a prefix and has this suffix
			// as a suffix, permit the operation.
			actionPrefix := strings.Split(allowedAction, wildcard)[0]
			actionSuffix := strings.Split(allowedAction, wildcard)[1]
			if strings.HasPrefix(operation, actionPrefix) && strings.HasSuffix(operation, actionSuffix) {
				permitOperation()
				break
			}
		}
	}

	// Now do not actions. We take away any permissions we may have granted already. Algorithm is
	// equivalent to above.
	for _, operation := range operations {
		denyOperation := func() {
			operationsPermitted[operation] = false
		}
		for _, unallowedAction := range notActions {
			if !hasWildcard(unallowedAction) {
				if operation == unallowedAction {
					denyOperation()
				}
				break
			}
			if len(unallowedAction) == 1 && unallowedAction == wildcard {
				denyOperation()
				break
			}
			if unallowedAction[0:1] == wildcard {
				actionSuffix := strings.TrimPrefix(unallowedAction, wildcard)
				if strings.HasSuffix(operation, actionSuffix) {
					denyOperation()
					break
				}
			}
			if unallowedAction[len(unallowedAction)-1:] == wildcard {
				actionPrefix := strings.TrimSuffix(unallowedAction, wildcard)
				if strings.HasPrefix(operation, actionPrefix) {
					denyOperation()
					break
				}
			}
			actionPrefix := strings.Split(unallowedAction, wildcard)[0]
			actionSuffix := strings.Split(unallowedAction, wildcard)[1]
			if strings.HasPrefix(operation, actionPrefix) && strings.HasSuffix(operation, actionSuffix) {
				denyOperation()
				break
			}
		}
	}

	// If any of the specified operations are denied, fail this part of the validation.
	for _, permitted := range operationsPermitted {
		if !permitted {
			return false, nil
		}
	}
	return true, nil
}

// numWildcards returns how many wildcards an action string has.
func numWildcards(action string) int {
	return strings.Count(action, wildcard)
}

// hasWildcard returns true IFF an action has one wildcard. Helper is useful for clarity in
// algorithm.
func hasWildcard(action string) bool {
	return numWildcards(action) == 1
}

// MapWithAllFalse when given a list of strings, creates and returns a map where each key is added
// to the map's set of keys with its value set to false.
func MapWithAllFalse(keys []string) map[string]bool {
	m := make(map[string]bool)
	for _, k := range keys {
		m[k] = false
	}
	return m
}
