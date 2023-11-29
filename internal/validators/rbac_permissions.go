package validators

import (
	"fmt"
	"strings"
)

const (
	wildcard = "*"
)

// deniedAction describes a candidate action and the NotAction configured in a role that denied it.
type deniedAction struct {
	candidateAction string
	denyingAction   string
}

// result summarizes data about how many actions were not permitted by a role's configuration and if
// they weren't permitted because they were included in the role's NotActions, which NotAction it
// was that denied it.
type result struct {
	missingFromActions  []string
	presentInNotActions []deniedAction
}

// processCandidateActions returns whether a list of Azure RBAC actions should be permitted based on
// a list of "actions" and "not actions" for a role definition, where actions are actions that the
// role definition explicitly permits and not actons are actions that the role definition explicitly
// denies, even if they would have been permitted based on the actions (not actions override
// actions). This works for both pairs of Actions and NotActions and pairs of DataActions and
// NotDataActions.
//
// Wildcards are taken into account, but only for the actions and not actions, with one wildcard
// permitted in the action or not action. Any more than that are invalid. Also, candidate actions do
// not support any wildcards. The args will be considered invalid and an error will be returned if
// these wildcard rules are not followed.
func processCandidateActions(candidateActions, actions, notActions []string) (result, error) {

	// Validate specified candidate Actions, Action data, and NotAction data.
	for _, ca := range candidateActions {
		if len(ca) == 0 {
			return result{}, fmt.Errorf("invalid candidate Action or DataAction in specified permissions, is empty string")
		}
		if numWildcards(ca) > 0 {
			return result{}, fmt.Errorf("invalid candidate Action or DataAction in specified permissions, has one or more wildcards")
		}
	}
	for _, a := range actions {
		if len(a) == 0 {
			return result{}, fmt.Errorf("invalid Action or DataAction in current role data, is empty string")
		}
		if numWildcards(a) > 1 {
			return result{}, fmt.Errorf("invalid Action or DataAction in current role data, has multiple  wildcards")
		}
	}
	for _, na := range notActions {
		if len(na) == 0 {
			return result{}, fmt.Errorf("invalid NotAction or DataNotAction in current role data, is empty string")
		}
		if numWildcards(na) > 1 {
			return result{}, fmt.Errorf("invalid NotAction or DataNotAction in current role data, has multiple wildcards")
		}
	}

	// Now we know all data is valid. We can figure out, for each candidate action, whether it
	// should be permitted based on the Actions and then whether it should be unpermitted based on
	// the NotActions. We also track, for each action we decide not to permit, why it isn't
	// permitted.
	unpermittedActions := map[string]bool{}
	result := result{
		missingFromActions:  []string{},
		presentInNotActions: []deniedAction{},
	}
	for _, candidateAction := range candidateActions {
		match := func(_ string) {
			// Intentional no-op
		}
		noMatch := func(_ string) {
			if ok := unpermittedActions[candidateAction]; !ok {
				result.missingFromActions = append(result.missingFromActions, candidateAction)
				unpermittedActions[candidateAction] = true
			}
		}
		processCandidateAction(candidateAction, actions, match, noMatch)
	}
	for _, candidateAction := range candidateActions {
		match := func(comparedAction string) {
			if ok := unpermittedActions[candidateAction]; !ok {
				result.presentInNotActions = append(result.presentInNotActions, deniedAction{
					candidateAction: candidateAction,
					denyingAction:   comparedAction,
				})
				unpermittedActions[candidateAction] = true
			}
		}
		noMatch := func(_ string) {
			// Intentional no-op
		}
		processCandidateAction(candidateAction, notActions, match, noMatch)
	}

	return result, nil
}

// processCandidateAction centralizes our logic for determining whether to permit or deny a
// candidate action (depending on whether we're doing the pass through the actions or the not
// actions). The logic for looking for wildcards, prefixes, suffixes, etc is the same for each
// compared list of actions.
//
// match and noMatch are hooks to run when there is either a match or no match during the iteration.
func processCandidateAction(candidateAction string, comparedActions []string, match, noMatch func(comparedAction string)) {

	for _, comparedAction := range comparedActions {
		if !hasWildcard(comparedAction) {
			// If allowed action has no wildcard, candidate action must be equal to it exactly
			// in order for the candidate action to be permitted.
			if candidateAction == comparedAction {
				match(comparedAction)
			}
			// Whether the action permitted the candidate action because it was equal to it or
			// it didn't, we can move on to the next action, because if it has no wildcard, it
			// is impossible for it to permit the candidate action via wildcard.
			continue
		}

		// Special case for when string is just a single char - the wildcard.
		if comparedAction == wildcard {
			match(comparedAction)
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
				match(comparedAction)
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
				match(comparedAction)
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
			match(comparedAction)
			continue
		}

		noMatch(comparedAction)
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
