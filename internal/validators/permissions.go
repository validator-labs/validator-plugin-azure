package validators

import (
	"fmt"
	"strings"
)

const (
	wildcard = "*"
)

// allCandidateActionsPermitted returns whether a list of Azure RBAC actions should be permitted
// based on a list of "actions" and "not actions" for a role definition from the Azure APIs, where
// actions are actions that the role definition explicitly permits and not actons are actions that
// the role definition explicitly denies, even if they would have been permitted based on the
// actions (not actions override actions).
//
// Wildcards are take into account, but only for the actions and not actions, with one wildcard
// permitted in the action or not action. Any more than that are invalid. Also, candidate actions do
// not support any wildcards. The args will be considered invalid and an error will be returned if
// these wildcard rules are not followed.
//
//   - candidateActions: The list of candidate actions.
//   - actions: The list of actions for the role definition.
//   - notActions: The list of not actions for the role definition.
func allCandidateActionsPermitted(candidateActions, actions, notActions []string) (bool, error) {

	// Create a map of strings and bools, with a key for every candidate action. Default each value
	// to false. They will be changed later to true if the set of actions allows them, and then set
	// back to false if the set of not actions unallows them.
	permittedCandidateActions := MapWithAllFalse(candidateActions)

	// Validate specified candidate actions, action data, and not action data.
	for _, ca := range candidateActions {
		if len(ca) == 0 {
			return false, fmt.Errorf("invalid candidate action in specified permissions, is empty string")
		}
		if numWildcards(ca) > 0 {
			return false, fmt.Errorf("invalid candidate action in specified permissions, has one or more wildcards")
		}
	}
	for _, a := range actions {
		if len(a) == 0 {
			return false, fmt.Errorf("invalid candidate action in set of actions in role's permissions, is empty string")
		}
		if numWildcards(a) > 1 {
			return false, fmt.Errorf("invalid candidate action in set of actions in role's permissions, has multiple  wildcards")
		}
	}
	for _, na := range notActions {
		if len(na) == 0 {
			return false, fmt.Errorf("invalid candidate action in set of not actions in role's permissions, is empty string")
		}
		if numWildcards(na) > 1 {
			return false, fmt.Errorf("invalid candidate action in set of not actions in role's permissions, has multiple wildcards")
		}
	}

	// Now we know all data is valid. We can figure out, for each candidate action, whether it
	// should be permitted based on the actions.
	for _, candidateAction := range candidateActions {
		processCandidateAction(candidateAction, actions, true, permittedCandidateActions)
	}
	for _, candidateAction := range candidateActions {
		processCandidateAction(candidateAction, notActions, false, permittedCandidateActions)
	}

	// If any of the specified candidate actions are denied, fail this part of the validation.
	for _, permitted := range permittedCandidateActions {
		if !permitted {
			return false, nil
		}
	}
	return true, nil
}

// processCandidateAction centralizes our logic for determining whether to permit or deny a
// candidate action (depending on whether we're doing the pass through the actions or the not
// actions). The logic for looking for wildcards, prefixes, suffixes, etc is the same for each
// compared list of actions. Mutates the map if it needs to permit or deny a candidate action.
//   - candidateAction: The candidate action.
//   - comparedActions: The list of actions we're comparing the action to during this operation.
//   - setPermittedTo: Whether to permit the action when the comparison criteria are met. If this
//     is true, flip the key to true, permitting the action. If this is false, we flip the key to
//     false, denying it after previously permitting it during the earlier function call.
//   - permittedCandidateActions: The map where we track what's permitted. Mutated if criteria are
//     met.
func processCandidateAction(candidateAction string, comparedActions []string, setPermittedTo bool, permittedCandidateActions map[string]bool) {

	for _, comparedAction := range comparedActions {
		if !hasWildcard(comparedAction) {
			// If allowed action has no wildcard, candidate action must be equal to it exactly
			// in order for the candidate action to be permitted.
			if candidateAction == comparedAction {
				permittedCandidateActions[candidateAction] = setPermittedTo
			}
			// Whether the action permitted the candidate action because it was equal to it or
			// it didn't, we can move on to the next action, because if it has no wildcard, it
			// is impossible for it to permit the candidate action via wildcard.
			continue
		}

		// Special case for when string is just a single char - the wildcard.
		if len(comparedAction) == 1 && comparedAction == wildcard {
			permittedCandidateActions[candidateAction] = setPermittedTo
			continue
		}

		// If allowed action string has a wildcard, candidate action must match when we take
		// the wildcard into account.

		if comparedAction[0:1] == wildcard {
			// Wildcard is at beginning of allowed action. No prefix in action string to take
			// into account.
			// Find the suffix of the action string. If that suffix is also a suffix of the
			// candidate action, permit the candidate action.
			actionSuffix := strings.TrimPrefix(comparedAction, wildcard)
			if strings.HasSuffix(candidateAction, actionSuffix) {
				permittedCandidateActions[candidateAction] = setPermittedTo
				continue
			}
		}

		if comparedAction[len(comparedAction)-1:] == wildcard {
			// Wildcard is at end of allowed action. No suffix in action string to take into
			// account.
			// Find the prefix of the action string. If that prefix is also a prefix of the
			// candidate action, permit the candidate action.
			actionPrefix := strings.TrimSuffix(comparedAction, wildcard)
			if strings.HasPrefix(candidateAction, actionPrefix) {
				permittedCandidateActions[candidateAction] = setPermittedTo
				continue
			}
		}

		// Wildcard is somewhere in the middle. Must take into account prefix and suffix.
		// Split the action string by the wildcard. The first segment is a prefix. The second is
		// a suffix. If the candidate action has this prefix as a prefix and has this suffix
		// as a suffix, permit the candidate action.
		splitAction := strings.Split(comparedAction, wildcard)
		actionPrefix := splitAction[0]
		actionSuffix := splitAction[1]
		if strings.HasPrefix(candidateAction, actionPrefix) && strings.HasSuffix(candidateAction, actionSuffix) {
			permittedCandidateActions[candidateAction] = setPermittedTo
			continue
		}
	}
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
